<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests\Unit;

final class PatchCommandRunnerTest extends \PHPUnit\Framework\TestCase
{
    public function testRunsRelockThenRepatchWithGuardAndNoDev(): void
    {
        $process = new ScriptedProcessRunner(results: ['patches-relock' => [0, "relocked\n"], 'patches-repatch' => [0, "repatched\n"]]);

        $output = $this->runner(process: $process)->run(cwd: '/project', devMode: false);

        self::assertSame("relocked\nrepatched\n", $output);
        self::assertSame(
            [
                ['/usr/bin/php', '/usr/bin/composer', 'patches-relock', '--no-scripts', '--no-interaction'],
                ['/usr/bin/php', '/usr/bin/composer', 'patches-repatch', '--no-scripts', '--no-interaction'],
            ],
            array_column($process->calls, 'command'),
        );
        self::assertSame(['/project', '/project'], array_column($process->calls, 'cwd'));
        self::assertSame(['PORTADESIGN_PATCHES_SYNC' => '1', 'COMPOSER_NO_DEV' => '1'], $process->calls[0]['env']);
    }

    public function testDevModeDoesNotForceNoDev(): void
    {
        $process = new ScriptedProcessRunner(results: []);

        $this->runner(process: $process)->run(cwd: '/project', devMode: true);

        self::assertSame(['PORTADESIGN_PATCHES_SYNC' => '1'], $process->calls[0]['env']);
    }

    public function testFailingRelockThrowsWithOutputAndSkipsRepatch(): void
    {
        $process = new ScriptedProcessRunner(results: ['patches-relock' => [2, "Your lock file does not contain a compatible set of packages.\n"]]);

        $thrown = null;
        try {
            $this->runner(process: $process)->run(cwd: '/project', devMode: false);
        } catch (\RuntimeException $e) {
            $thrown = $e;
        }

        self::assertSame(
            "composer patches-relock failed with exit code 2:\nYour lock file does not contain a compatible set of packages.\n",
            $thrown?->getMessage(),
        );
        self::assertCount(1, $process->calls);
    }

    public function testFailingRepatchThrowsWithCombinedOutput(): void
    {
        $process = new ScriptedProcessRunner(results: ['patches-relock' => [0, "relocked\n"], 'patches-repatch' => [1, "platform check failed\n"]]);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage("composer patches-repatch failed with exit code 1:\nrelocked\nplatform check failed\n\nrun \"composer install\" to restore vendor/");

        $this->runner(process: $process)->run(cwd: '/project', devMode: false);
    }

    /**
     * @return array<string, array{list<string>, array<string, string>}>
     */
    public static function platformOptionProvider(): array
    {
        return [
            'none' => [['composer', 'install'], []],
            'ignore all' => [['composer', 'install', '--ignore-platform-reqs'], ['COMPOSER_IGNORE_PLATFORM_REQS' => '1']],
            'inline value' => [['composer', 'require', 'a/b', '--ignore-platform-req=php'], ['COMPOSER_IGNORE_PLATFORM_REQ' => 'php']],
            'separate value' => [['composer', 'require', '--ignore-platform-req', 'php', 'a/b'], ['COMPOSER_IGNORE_PLATFORM_REQ' => 'php']],
            'repeated' => [['composer', 'update', '--ignore-platform-req=php', '--ignore-platform-req=ext-gd'], ['COMPOSER_IGNORE_PLATFORM_REQ' => 'php,ext-gd']],
            'mixed styles' => [['composer', 'update', '--ignore-platform-req', 'php', '--ignore-platform-req=ext-gd'], ['COMPOSER_IGNORE_PLATFORM_REQ' => 'php,ext-gd']],
            'ignore all and list' => [['composer', 'update', '--ignore-platform-reqs', '--ignore-platform-req=php'], ['COMPOSER_IGNORE_PLATFORM_REQS' => '1', 'COMPOSER_IGNORE_PLATFORM_REQ' => 'php']],
            'separate value missing' => [['composer', 'update', '--ignore-platform-req', '--no-dev'], []],
            'after double dash is a script argument' => [['composer', 'run', 'x', '--', '--ignore-platform-reqs'], []],
            'duplicate value' => [['composer', 'update', '--ignore-platform-req=php', '--ignore-platform-req=php'], ['COMPOSER_IGNORE_PLATFORM_REQ' => 'php']],
            'empty inline value' => [['composer', 'update', '--ignore-platform-req='], []],
            'unrelated options' => [['composer', 'install', '--no-dev', '-o'], []],
        ];
    }

    /**
     * @param list<string> $arguments
     * @param array<string, string> $expected
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('platformOptionProvider')]
    public function testPlatformRequirementsAreForwardedAsEnvironment(array $arguments, array $expected): void
    {
        $process = new ScriptedProcessRunner(results: []);

        $this->runner(process: $process, arguments: $arguments)->run(cwd: '/project', devMode: true);

        $expectedEnv = ['PORTADESIGN_PATCHES_SYNC' => '1', ...$expected];
        self::assertSame($expectedEnv, $process->calls[0]['env']);
        self::assertSame($expectedEnv, $process->calls[1]['env']);
        self::assertSame(['/usr/bin/php', '/usr/bin/composer', 'patches-relock', '--no-scripts', '--no-interaction'], $process->calls[0]['command']);
        self::assertSame(['/usr/bin/php', '/usr/bin/composer', 'patches-repatch', '--no-scripts', '--no-interaction'], $process->calls[1]['command']);
    }

    /**
     * @param list<string> $arguments
     */
    private function runner(ScriptedProcessRunner $process, array $arguments = []): \Portadesign\PimcoreSecurityPatches\PatchCommandRunner
    {
        return new \Portadesign\PimcoreSecurityPatches\PatchCommandRunner(
            runner: $process,
            phpBinary: '/usr/bin/php',
            composerBinary: '/usr/bin/composer',
            parentArguments: $arguments,
        );
    }
}
