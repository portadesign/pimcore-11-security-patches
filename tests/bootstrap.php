<?php

declare(strict_types=1);

$projectRoot = getenv('PIMCORE_PROJECT_ROOT') ?: dirname(__DIR__, 4);

if (!is_file($projectRoot . '/vendor/autoload.php')) {
    $projectRoot = (string) getcwd();
}

if (!is_file($projectRoot . '/vendor/autoload.php')) {
    fwrite(STDERR, "Host project not found. Run from the project root or set PIMCORE_PROJECT_ROOT.\n");

    exit(1);
}

define('PIMCORE_PROJECT_ROOT', realpath($projectRoot));

require_once PIMCORE_PROJECT_ROOT . '/vendor/autoload.php';

Pimcore\Bootstrap::setProjectRoot();
Pimcore\Bootstrap::bootstrap();
Pimcore\Bootstrap::kernel();

spl_autoload_register(static function (string $class): void {
    $prefix = 'Portadesign\\PimcoreSecurityPatches\\Tests\\';

    if (!str_starts_with($class, $prefix)) {
        return;
    }

    $file = __DIR__ . '/' . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';

    if (is_file($file)) {
        require_once $file;
    }
});
