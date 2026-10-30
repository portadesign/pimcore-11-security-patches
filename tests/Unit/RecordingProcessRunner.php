<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests\Unit;

final class RecordingProcessRunner implements \Portadesign\PimcoreSecurityPatches\ProcessRunner
{
    /**
     * @var list<array{command: list<string>, cwd: string, env: array<string, string>}>
     */
    public array $calls = [];

    /**
     * @param array<string, int> $exitCodes
     */
    public function __construct(private readonly array $exitCodes)
    {
    }

    public function run(array $command, string $cwd, array $env = []): int
    {
        $this->calls[] = ['command' => $command, 'cwd' => $cwd, 'env' => $env];

        return $this->exitCodes[$command[0]] ?? 0;
    }
}
