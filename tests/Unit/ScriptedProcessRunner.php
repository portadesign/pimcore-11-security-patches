<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests\Unit;

final class ScriptedProcessRunner implements \Portadesign\PimcoreSecurityPatches\ProcessRunner
{
    /**
     * @var list<array{command: list<string>, cwd: string, env: array<string, string>}>
     */
    public array $calls = [];

    private string $lastOutput = '';

    /**
     * @param array<string, array{int, string}> $results exit code and output keyed by the composer command name
     */
    public function __construct(private readonly array $results)
    {
    }

    public function run(array $command, string $cwd, array $env = []): int
    {
        $this->calls[] = ['command' => $command, 'cwd' => $cwd, 'env' => $env];
        [$exitCode, $this->lastOutput] = $this->results[$command[2]] ?? [0, ''];

        return $exitCode;
    }

    public function lastOutput(): string
    {
        return $this->lastOutput;
    }
}
