<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests\Support;

final class DeserializationCanary
{
    public static int $executions = 0;

    public function __wakeup(): void
    {
        self::$executions++;
    }

    public function __destruct()
    {
        self::$executions++;
    }

    public static function serialized(\Closure $factory): string
    {
        $payload = serialize($factory());
        self::reset();

        return $payload;
    }

    public static function reset(): void
    {
        self::$executions = 0;
    }
}
