<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches;

final readonly class ComposerProcessRunner implements ProcessRunner
{
    public function __construct(private \Composer\Util\ProcessExecutor $executor)
    {
    }

    /**
     * {@inheritDoc}
     */
    public function run(array $command, string $cwd, array $env = []): int
    {
        $previous = [];
        foreach ($env as $name => $value) {
            $previous[$name] = \Composer\Util\Platform::getEnv(name: $name);
            \Composer\Util\Platform::putEnv(name: $name, value: $value);
        }

        try {
            $output = '';

            return $this->executor->execute(command: $command, output: $output, cwd: $cwd);
        } finally {
            foreach ($previous as $name => $value) {
                if (false === $value) {
                    \Composer\Util\Platform::clearEnv(name: $name);
                } else {
                    \Composer\Util\Platform::putEnv(name: $name, value: $value);
                }
            }
        }
    }
}
