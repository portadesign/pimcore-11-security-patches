<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches;

interface ProcessRunner
{
    /**
     * @param non-empty-list<string> $command
     * @param array<non-empty-string, string> $env
     */
    public function run(array $command, string $cwd, array $env = []): int;
}
