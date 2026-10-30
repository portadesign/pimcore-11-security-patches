<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests\Unit;

final class InstalledPatchInspectorTest extends \PHPUnit\Framework\TestCase
{
    private const PATCH = <<<'PATCH'
diff --git a/f.txt b/f.txt
--- a/f.txt
+++ b/f.txt
@@ -1,2 +1,2 @@
 a
-b
+c

PATCH;

    private string $workDir;

    protected function setUp(): void
    {
        $this->workDir = sys_get_temp_dir() . '/psp-' . bin2hex(random_bytes(6));
        mkdir(directory: $this->workDir . '/bundled', recursive: true);
        mkdir(directory: $this->workDir . '/install/pkg', recursive: true);
    }

    protected function tearDown(): void
    {
        (new \Symfony\Component\Filesystem\Filesystem())->remove($this->workDir);
    }

    public function testPatchBinaryIsUsedWhenAvailable(): void
    {
        $runner = new RecordingProcessRunner(exitCodes: ['patch' => 0]);
        $inspector = $this->inspector(runner: $runner, io: new \Composer\IO\BufferIO());

        $status = $inspector->inspect(patch: $this->localPatch(), installPath: '/install/pkg');

        self::assertSame(\Portadesign\PimcoreSecurityPatches\PatchStatus::Applied, $status);
        self::assertCount(1, $runner->calls);
        self::assertSame(['patch', '-p1', '--dry-run', '-R', '-s', '-f', '--batch', '-i', '/p/a.patch'], $runner->calls[0]['command']);
        self::assertSame('/install/pkg', $runner->calls[0]['cwd']);
    }

    public function testPatchRejectingReverseDryRunMeansMissingWithoutGitFallback(): void
    {
        $runner = new RecordingProcessRunner(exitCodes: ['patch' => 1, 'git' => 0]);
        $inspector = $this->inspector(runner: $runner, io: new \Composer\IO\BufferIO());

        $status = $inspector->inspect(patch: $this->localPatch(), installPath: '/install/pkg');

        self::assertSame(\Portadesign\PimcoreSecurityPatches\PatchStatus::Missing, $status);
        self::assertCount(1, $runner->calls);
    }

    public function testGitApplyIsUsedWithCeilingWhenPatchIsMissing(): void
    {
        $runner = new RecordingProcessRunner(exitCodes: ['patch' => 127, 'git' => 0]);
        $inspector = $this->inspector(runner: $runner, io: new \Composer\IO\BufferIO());
        $patch = $this->localPatch();
        $patch->depth = 2;

        $status = $inspector->inspect(patch: $patch, installPath: '/install/pkg');

        self::assertSame(\Portadesign\PimcoreSecurityPatches\PatchStatus::Applied, $status);
        self::assertCount(2, $runner->calls);
        self::assertSame(['git', 'apply', '--check', '-R', '-p2', '/p/a.patch'], $runner->calls[1]['command']);
        self::assertSame('/install/pkg', $runner->calls[1]['cwd']);
        self::assertSame(['GIT_CEILING_DIRECTORIES' => '/install'], $runner->calls[1]['env']);
    }

    public function testGitApplyFailureMeansMissing(): void
    {
        $runner = new RecordingProcessRunner(exitCodes: ['patch' => 127, 'git' => 1]);
        $inspector = $this->inspector(runner: $runner, io: new \Composer\IO\BufferIO());

        $status = $inspector->inspect(patch: $this->localPatch(), installPath: '/install/pkg');

        self::assertSame(\Portadesign\PimcoreSecurityPatches\PatchStatus::Missing, $status);
    }

    public function testNeitherToolWarnsOnceAndCountsNothing(): void
    {
        $io = new \Composer\IO\BufferIO();
        $inspector = $this->inspector(runner: new RecordingProcessRunner(exitCodes: ['patch' => 127, 'git' => 127]), io: $io);
        $targets = [
            'vendor/one' => ['installPath' => '/install/one', 'patches' => [$this->localPatch(), $this->localPatch()]],
            'vendor/two' => ['installPath' => '/install/two', 'patches' => [$this->localPatch()]],
        ];

        $result = $inspector->inspectAll(targets: $targets);

        self::assertSame(['checked' => 0, 'missing' => []], $result);
        self::assertSame(1, substr_count($io->getOutput(), 'neither patch nor git found, cannot verify patches'));
    }

    public function testNoWarningWhenToolsWork(): void
    {
        $io = new \Composer\IO\BufferIO();
        $inspector = $this->inspector(runner: new RecordingProcessRunner(exitCodes: ['patch' => 1]), io: $io);

        $result = $inspector->inspectAll(targets: ['vendor/one' => ['installPath' => '/install/one', 'patches' => [$this->localPatch()]]]);

        self::assertSame(['checked' => 1, 'missing' => ['vendor/one' => 1]], $result);
        self::assertSame('', $io->getOutput());
    }

    public function testRealGitFallbackDetectsAppliedAndMissingOutsideARepository(): void
    {
        $patchFile = $this->workDir . '/a.patch';
        file_put_contents(filename: $patchFile, data: self::PATCH);
        $install = $this->workDir . '/install/pkg';
        $runner = new PatchlessProcessRunner(inner: new \Portadesign\PimcoreSecurityPatches\ComposerProcessRunner(executor: new \Composer\Util\ProcessExecutor()));
        $inspector = $this->inspector(runner: $runner, io: new \Composer\IO\BufferIO());
        $patch = $this->localPatch(path: $patchFile);

        file_put_contents(filename: $install . '/f.txt', data: "a\nb\n");
        self::assertSame(\Portadesign\PimcoreSecurityPatches\PatchStatus::Missing, $inspector->inspect(patch: $patch, installPath: $install));

        file_put_contents(filename: $install . '/f.txt', data: "a\nc\n");
        self::assertSame(\Portadesign\PimcoreSecurityPatches\PatchStatus::Applied, $inspector->inspect(patch: $patch, installPath: $install));
    }

    public function testBundledFileWithMatchingHashSkipsDownload(): void
    {
        file_put_contents(filename: $this->workDir . '/bundled/a.patch', data: self::PATCH);
        $downloads = 0;
        $runner = new RecordingProcessRunner(exitCodes: ['patch' => 0]);
        $inspector = $this->inspector(runner: $runner, io: new \Composer\IO\BufferIO(), download: static function () use (&$downloads): void {
            ++$downloads;
        });
        $patch = $this->remotePatch(sha256: hash(algo: 'sha256', data: self::PATCH));

        $status = $inspector->inspect(patch: $patch, installPath: '/install/pkg');

        self::assertSame(\Portadesign\PimcoreSecurityPatches\PatchStatus::Applied, $status);
        self::assertSame(0, $downloads);
        self::assertSame($this->workDir . '/bundled/a.patch', $runner->calls[0]['command'][8]);
    }

    public function testBundledFileWithDifferentHashFallsBackToDownload(): void
    {
        file_put_contents(filename: $this->workDir . '/bundled/a.patch', data: self::PATCH);
        $runner = new RecordingProcessRunner(exitCodes: ['patch' => 0]);
        $inspector = $this->inspector(runner: $runner, io: new \Composer\IO\BufferIO(), download: static function (\cweagans\Composer\Patch $patch): void {
            $patch->localPath = '/downloaded/a.patch';
        });

        $inspector->inspect(patch: $this->remotePatch(sha256: str_repeat('0', 64)), installPath: '/install/pkg');

        self::assertSame('/downloaded/a.patch', $runner->calls[0]['command'][8]);
    }

    public function testPatchWithoutHashIsDownloadedEvenWhenBundled(): void
    {
        file_put_contents(filename: $this->workDir . '/bundled/a.patch', data: self::PATCH);
        $runner = new RecordingProcessRunner(exitCodes: ['patch' => 0]);
        $inspector = $this->inspector(runner: $runner, io: new \Composer\IO\BufferIO(), download: static function (\cweagans\Composer\Patch $patch): void {
            $patch->localPath = '/downloaded/a.patch';
        });

        $inspector->inspect(patch: $this->remotePatch(sha256: null), installPath: '/install/pkg');

        self::assertSame('/downloaded/a.patch', $runner->calls[0]['command'][8]);
    }

    public function testDownloadFailureWarnsAndSkipsVerification(): void
    {
        $io = new \Composer\IO\BufferIO();
        $runner = new RecordingProcessRunner(exitCodes: ['patch' => 1]);
        $inspector = $this->inspector(runner: $runner, io: $io, download: static function (): void {
            throw new \RuntimeException('connection refused');
        });
        $targets = ['vendor/one' => ['installPath' => '/install/one', 'patches' => [$this->remotePatch(sha256: null)]]];

        $result = $inspector->inspectAll(targets: $targets);

        self::assertSame(['checked' => 0, 'missing' => []], $result);
        self::assertSame([], $runner->calls);
        self::assertStringContainsString('https://example.test/patches/a.patch', $io->getOutput());
        self::assertStringContainsString('connection refused', $io->getOutput());
    }

    public function testComposerProcessRunnerPassesAndRestoresEnvironment(): void
    {
        $runner = new \Portadesign\PimcoreSecurityPatches\ComposerProcessRunner(executor: new \Composer\Util\ProcessExecutor());

        $withEnv = $runner->run(command: ['sh', '-c', 'test "$PSP_TEST_VAR" = value'], cwd: $this->workDir, env: ['PSP_TEST_VAR' => 'value']);
        $withoutEnv = $runner->run(command: ['sh', '-c', 'test "$PSP_TEST_VAR" = value'], cwd: $this->workDir);

        self::assertSame(0, $withEnv);
        self::assertSame(1, $withoutEnv);
        self::assertFalse(\Composer\Util\Platform::getEnv(name: 'PSP_TEST_VAR'));
    }

    private function inspector(
        \Portadesign\PimcoreSecurityPatches\ProcessRunner $runner,
        \Composer\IO\IOInterface $io,
        ?\Closure $download = null,
    ): \Portadesign\PimcoreSecurityPatches\InstalledPatchInspector {
        return new \Portadesign\PimcoreSecurityPatches\InstalledPatchInspector(
            runner: $runner,
            download: $download ?? static function (): void {
            },
            io: $io,
            bundledDirectory: $this->workDir . '/bundled',
        );
    }

    private function localPatch(string $path = '/p/a.patch'): \cweagans\Composer\Patch
    {
        $patch = $this->remotePatch(sha256: null);
        $patch->localPath = $path;

        return $patch;
    }

    private function remotePatch(?string $sha256): \cweagans\Composer\Patch
    {
        $patch = new \cweagans\Composer\Patch();
        $patch->package = 'vendor/one';
        $patch->description = 'test';
        $patch->url = 'https://example.test/patches/a.patch';
        $patch->sha256 = $sha256;

        return $patch;
    }
}
