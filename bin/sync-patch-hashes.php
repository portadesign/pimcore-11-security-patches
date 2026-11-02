#!/usr/bin/env php
<?php

declare(strict_types=1);

$root = dirname(path: __DIR__);
$composerFile = $root . '/composer.json';
$contents = (string) file_get_contents(filename: $composerFile);
$missing = [];

$updated = preg_replace_callback(
    pattern: '#("url":\s*"[^"]*/patches/([^"/]+)",\s*"sha256":\s*")[0-9a-f]*(")#',
    callback: static function (array $match) use ($root, &$missing): string {
        $file = $root . '/patches/' . $match[2];
        if (!is_file(filename: $file)) {
            $missing[] = $match[2];

            return $match[0];
        }

        return $match[1] . hash_file(algo: 'sha256', filename: $file) . $match[3];
    },
    subject: $contents,
);

if (null === $updated || [] !== $missing) {
    fwrite(STDERR, 'sync-patch-hashes: missing patch files: ' . implode(separator: ', ', array: $missing) . "\n");

    exit(1);
}

file_put_contents(filename: $composerFile, data: $updated);
