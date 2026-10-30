<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests\Unit;

final readonly class PatchlessProcessRunner implements \Portadesign\PimcoreSecurityPatches\ProcessRunner
{
    public function __construct(private \Portadesign\PimcoreSecurityPatches\ProcessRunner $inner)
    {
    }

    public function run(array $command, string $cwd, array $env = []): int
    {
        if ('patch' === $command[0]) {
            return 127;
        }

        return $this->inner->run(command: $command, cwd: $cwd, env: $env);
    }
}
