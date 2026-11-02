<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests\Unit;

final class ComposerProcessRunnerTest extends \PHPUnit\Framework\TestCase
{
    private const VARIABLE = 'PSP_TEST_RUNNER_VAR';

    private const OTHER_VARIABLE = 'PSP_TEST_RUNNER_OTHER';

    protected function setUp(): void
    {
        $this->clear();
    }

    protected function tearDown(): void
    {
        $this->clear();
    }

    public function testVariableIsVisibleToChildAndClearedAfterwards(): void
    {
        $exitCode = $this->runner()->run(command: $this->expectValue(name: self::VARIABLE, value: 'child'), cwd: sys_get_temp_dir(), env: [self::VARIABLE => 'child']);

        self::assertSame(0, $exitCode);
        self::assertFalse(\Composer\Util\Platform::getEnv(name: self::VARIABLE));
        self::assertArrayNotHasKey(self::VARIABLE, $_SERVER);
        self::assertFalse(getenv(self::VARIABLE));
    }

    public function testVariableIsNotVisibleWithoutEnv(): void
    {
        $exitCode = $this->runner()->run(command: $this->expectValue(name: self::VARIABLE, value: 'child'), cwd: sys_get_temp_dir());

        self::assertSame(1, $exitCode);
    }

    public function testPreExistingValueIsOverriddenForChildAndRestored(): void
    {
        \Composer\Util\Platform::putEnv(name: self::VARIABLE, value: 'original');

        $overridden = $this->runner()->run(command: $this->expectValue(name: self::VARIABLE, value: 'child'), cwd: sys_get_temp_dir(), env: [self::VARIABLE => 'child']);

        self::assertSame(0, $overridden);
        self::assertSame('original', \Composer\Util\Platform::getEnv(name: self::VARIABLE));
        self::assertSame('original', getenv(self::VARIABLE));
        self::assertSame(0, $this->runner()->run(command: $this->expectValue(name: self::VARIABLE, value: 'original'), cwd: sys_get_temp_dir()));
    }

    public function testEveryVariableIsRestoredIndependently(): void
    {
        \Composer\Util\Platform::putEnv(name: self::OTHER_VARIABLE, value: 'kept');

        $this->runner()->run(
            command: ['true'],
            cwd: sys_get_temp_dir(),
            env: [self::VARIABLE => 'one', self::OTHER_VARIABLE => 'two'],
        );

        self::assertFalse(\Composer\Util\Platform::getEnv(name: self::VARIABLE));
        self::assertSame('kept', \Composer\Util\Platform::getEnv(name: self::OTHER_VARIABLE));
    }

    public function testEnvironmentIsRestoredWhenTheExecutorThrows(): void
    {
        \Composer\Util\Platform::putEnv(name: self::OTHER_VARIABLE, value: 'kept');
        $runner = new \Portadesign\PimcoreSecurityPatches\ComposerProcessRunner(executor: new class extends \Composer\Util\ProcessExecutor {
            public function execute($command, &$output = null, ?string $cwd = null): int
            {
                throw new \LogicException('executor failed');
            }
        });

        $thrown = null;
        try {
            $runner->run(command: ['true'], cwd: sys_get_temp_dir(), env: [self::VARIABLE => 'one', self::OTHER_VARIABLE => 'two']);
        } catch (\LogicException $exception) {
            $thrown = $exception;
        }

        self::assertSame('executor failed', $thrown?->getMessage());
        self::assertFalse(\Composer\Util\Platform::getEnv(name: self::VARIABLE));
        self::assertSame('kept', \Composer\Util\Platform::getEnv(name: self::OTHER_VARIABLE));
    }

    public function testLastOutputCombinesStdoutAndStderrOfTheLatestRun(): void
    {
        $runner = $this->runner();

        $runner->run(command: ['sh', '-c', 'echo first'], cwd: sys_get_temp_dir());
        self::assertSame("first\n", $runner->lastOutput());

        $runner->run(command: ['sh', '-c', 'echo out; echo err >&2; exit 3'], cwd: sys_get_temp_dir());
        self::assertStringContainsString('out', $runner->lastOutput());
        self::assertStringContainsString('err', $runner->lastOutput());
        self::assertStringNotContainsString('first', $runner->lastOutput());
    }

    public function testExitCodeIsReturned(): void
    {
        self::assertSame(3, $this->runner()->run(command: ['sh', '-c', 'exit 3'], cwd: sys_get_temp_dir()));
    }

    private function runner(): \Portadesign\PimcoreSecurityPatches\ComposerProcessRunner
    {
        return new \Portadesign\PimcoreSecurityPatches\ComposerProcessRunner(executor: new \Composer\Util\ProcessExecutor());
    }

    /**
     * @return non-empty-list<string>
     */
    private function expectValue(string $name, string $value): array
    {
        return ['sh', '-c', sprintf('test "$%s" = %s', $name, escapeshellarg($value))];
    }

    private function clear(): void
    {
        \Composer\Util\Platform::clearEnv(name: self::VARIABLE);
        \Composer\Util\Platform::clearEnv(name: self::OTHER_VARIABLE);
    }
}
