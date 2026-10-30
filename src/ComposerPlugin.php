<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches;

final readonly class ComposerPlugin implements \Composer\Plugin\PluginInterface, \Composer\EventDispatcher\EventSubscriberInterface
{
    private const GUARD_ENV = 'PORTADESIGN_PATCHES_SYNC';

    private const COMMAND_NOT_FOUND = 127;

    private const PATCH_COMMANDS = ['patches-relock', 'patches-repatch'];

    public function activate(\Composer\Composer $composer, \Composer\IO\IOInterface $io): void
    {
    }

    public function deactivate(\Composer\Composer $composer, \Composer\IO\IOInterface $io): void
    {
    }

    public function uninstall(\Composer\Composer $composer, \Composer\IO\IOInterface $io): void
    {
    }

    /**
     * @return array<string, string>
     */
    public static function getSubscribedEvents(): array
    {
        return [
            \Composer\Script\ScriptEvents::POST_INSTALL_CMD => 'synchronize',
            \Composer\Script\ScriptEvents::POST_UPDATE_CMD => 'synchronize',
        ];
    }

    public function synchronize(\Composer\Script\Event $event): void
    {
        if (false !== \Composer\Util\Platform::getEnv(name: self::GUARD_ENV)) {
            return;
        }

        $composer = $event->getComposer();
        $patchesPlugin = $this->findPatchesPlugin(composer: $composer);
        if (null === $patchesPlugin) {
            return;
        }

        $disabledResolvers = $patchesPlugin->getConfig(key: 'disable-resolvers');
        $resolved = (new \cweagans\Composer\Resolver(
            composer: $composer,
            io: new \Composer\IO\NullIO(),
            disabledResolvers: is_array($disabledResolvers) ? $disabledResolvers : [],
        ))->loadFromResolvers();

        $io = $event->getIO();
        $reason = $this->detectDrift(patchesPlugin: $patchesPlugin, resolved: $resolved);

        if (null === $reason) {
            $inspection = $this->inspectInstalledPatches(composer: $composer, patchesPlugin: $patchesPlugin, io: $io);
            if ([] === $inspection['missing']) {
                if ($inspection['checked'] > 0) {
                    $io->write(messages: sprintf('pimcore-11-security-patches: all %d patches applied', $inspection['checked']));
                }

                return;
            }

            foreach ($inspection['missing'] as $package => $count) {
                $io->write(messages: sprintf('pimcore-11-security-patches: %d patch(es) missing in %s, re-applying', $count, $package));
            }
        } else {
            $io->write(messages: sprintf('pimcore-11-security-patches: %s, relocking and re-applying patches', $reason));
        }

        $patched = $this->installedPatchedPackages(composer: $composer, collection: $resolved);
        $this->runPatchCommands(io: $io, devMode: $event->isDevMode());
        $this->assertInstalled(composer: $composer, patchedPackages: $patched);
        $io->write(messages: sprintf(
            'pimcore-11-security-patches: patches applied to %s',
            [] === $patched ? 'no packages' : implode(separator: ', ', array: $patched),
        ));
    }

    /**
     * @return array{checked: int, missing: array<string, int>}
     */
    private function inspectInstalledPatches(
        \Composer\Composer $composer,
        \cweagans\Composer\Plugin\Patches $patchesPlugin,
        \Composer\IO\IOInterface $io,
    ): array {
        if (!$patchesPlugin->getLocker()->isLocked()) {
            return ['checked' => 0, 'missing' => []];
        }

        $locked = \cweagans\Composer\PatchCollection::fromJson($patchesPlugin->getLocker()->getLockData());
        $repository = $composer->getRepositoryManager()->getLocalRepository();
        $executor = new \Composer\Util\ProcessExecutor($io);
        $checked = 0;
        $missing = [];

        foreach ($this->patchedPackages(collection: $locked) as $name) {
            $package = $repository->findPackage(name: $name, constraint: '*');
            $installPath = null === $package ? null : $composer->getInstallationManager()->getInstallPath(package: $package);
            if (null === $installPath) {
                continue;
            }

            foreach ($locked->getPatchesForPackage(package: $name) as $patch) {
                if (!$patch instanceof \cweagans\Composer\Patch) {
                    continue;
                }

                $patchesPlugin->download(patch: $patch);
                ++$checked;
                if (!$this->isApplied(executor: $executor, patch: $patch, installPath: $installPath)) {
                    $missing[$name] = ($missing[$name] ?? 0) + 1;
                }
            }
        }

        return ['checked' => $checked, 'missing' => $missing];
    }

    private function isApplied(\Composer\Util\ProcessExecutor $executor, \cweagans\Composer\Patch $patch, string $installPath): bool
    {
        $file = $patch->localPath ?? null;
        if (null === $file) {
            return false;
        }

        $strip = '-p' . ($patch->depth ?? 1);
        $output = '';
        $exitCode = $executor->execute(
            command: ['patch', $strip, '--dry-run', '-R', '-s', '-f', '--batch', '-i', $file],
            output: $output,
            cwd: $installPath,
        );

        if (self::COMMAND_NOT_FOUND !== $exitCode || !is_dir(filename: $installPath . '/.git')) {
            return 0 === $exitCode;
        }

        return 0 === $executor->execute(command: ['git', 'apply', '--check', '-R', $strip, $file], output: $output, cwd: $installPath);
    }

    private function findPatchesPlugin(\Composer\Composer $composer): ?\cweagans\Composer\Plugin\Patches
    {
        foreach ($composer->getPluginManager()->getPlugins() as $plugin) {
            if ($plugin instanceof \cweagans\Composer\Plugin\Patches) {
                return $plugin;
            }
        }

        return null;
    }

    private function detectDrift(\cweagans\Composer\Plugin\Patches $patchesPlugin, \cweagans\Composer\PatchCollection $resolved): ?string
    {
        $locker = $patchesPlugin->getLocker();
        $lockName = basename(path: $patchesPlugin->getLockFile()->getPath());

        if (!$locker->isLocked()) {
            return [] === $this->patchedPackages(collection: $resolved) ? null : sprintf('%s is missing', $lockName);
        }

        $locked = $this->index(collection: \cweagans\Composer\PatchCollection::fromJson($locker->getLockData()));
        $wanted = $this->index(collection: $resolved);

        if (array_keys($locked) !== array_keys($wanted)) {
            return sprintf('%s is out of date', $lockName);
        }

        foreach ($wanted as $key => $sha256) {
            if (null !== $sha256 && $sha256 !== $locked[$key]) {
                return sprintf('%s has a different checksum for a patch', $lockName);
            }
        }

        return null;
    }

    /**
     * @return list<string>
     */
    private function patchedPackages(\cweagans\Composer\PatchCollection $collection): array
    {
        return array_values(array: array_filter(array: $collection->getPatchedPackages(), callback: 'is_string'));
    }

    /**
     * @return list<string>
     */
    private function installedPatchedPackages(\Composer\Composer $composer, \cweagans\Composer\PatchCollection $collection): array
    {
        $repository = $composer->getRepositoryManager()->getLocalRepository();

        return array_values(array: array_filter(
            array: $this->patchedPackages(collection: $collection),
            callback: static fn (string $name): bool => null !== $repository->findPackage(name: $name, constraint: '*'),
        ));
    }

    /**
     * @return array<string, string|null>
     */
    private function index(\cweagans\Composer\PatchCollection $collection): array
    {
        $index = [];
        foreach ($this->patchedPackages(collection: $collection) as $package) {
            foreach ($collection->getPatchesForPackage(package: $package) as $patch) {
                if (!$patch instanceof \cweagans\Composer\Patch) {
                    continue;
                }

                $index[$package . ' ' . $patch->url] = $patch->sha256 ?? null;
            }
        }
        ksort(array: $index);

        return $index;
    }

    private function runPatchCommands(\Composer\IO\IOInterface $io, bool $devMode): void
    {
        $composerBinary = \Composer\Util\Platform::getEnv(name: 'COMPOSER_BINARY');
        if (!is_string($composerBinary) || '' === $composerBinary) {
            throw new \RuntimeException('COMPOSER_BINARY is not set, cannot run the patches commands.');
        }

        $previousNoDev = \Composer\Util\Platform::getEnv(name: 'COMPOSER_NO_DEV');
        \Composer\Util\Platform::putEnv(name: self::GUARD_ENV, value: '1');
        if (!$devMode) {
            \Composer\Util\Platform::putEnv(name: 'COMPOSER_NO_DEV', value: '1');
        }

        try {
            $executor = new \Composer\Util\ProcessExecutor($io);
            foreach (self::PATCH_COMMANDS as $command) {
                $output = '';
                $exitCode = $executor->execute(
                    command: [PHP_BINARY, $composerBinary, $command, '--no-scripts', '--no-interaction'],
                    output: $output,
                );
                if (0 !== $exitCode) {
                    throw new \RuntimeException(sprintf("%s failed:\n%s%s", $command, is_string($output) ? $output : '', $executor->getErrorOutput()));
                }
            }
        } finally {
            \Composer\Util\Platform::clearEnv(name: self::GUARD_ENV);
            if (false === $previousNoDev) {
                \Composer\Util\Platform::clearEnv(name: 'COMPOSER_NO_DEV');
            } else {
                \Composer\Util\Platform::putEnv(name: 'COMPOSER_NO_DEV', value: $previousNoDev);
            }
        }
    }

    /**
     * @param list<string> $patchedPackages
     */
    private function assertInstalled(\Composer\Composer $composer, array $patchedPackages): void
    {
        $vendorDir = $composer->getConfig()->get(key: 'vendor-dir');
        if (!is_string($vendorDir)) {
            throw new \RuntimeException('vendor-dir is not configured.');
        }

        $installed = new \Composer\Repository\FilesystemRepository(
            repositoryFile: new \Composer\Json\JsonFile(path: $vendorDir . '/composer/installed.json'),
        );

        foreach ($patchedPackages as $name) {
            if (null === $installed->findPackage(name: $name, constraint: '*')) {
                throw new \RuntimeException(sprintf('%s is missing after re-applying patches, run "composer install".', $name));
            }
        }
    }
}
