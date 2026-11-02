<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches;

final class ComposerProcessRunner implements ProcessRunner
{
    private string $lastOutput = '';

    public function __construct(private readonly \Composer\Util\ProcessExecutor $executor)
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
            $exitCode = $this->executor->execute(command: $command, output: $output, cwd: $cwd);
            $this->lastOutput = (is_string($output) ? $output : '') . $this->executor->getErrorOutput();

            return $exitCode;
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

    public function lastOutput(): string
    {
        return $this->lastOutput;
    }
}
