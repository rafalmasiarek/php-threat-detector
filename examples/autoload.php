<?php

declare(strict_types=1);

/**
 * Minimal PSR-4 autoloader for demo purposes (no Composer).
 * Maps the namespace prefix 'rafalmasiarek\Threat\' to the library 'src/' directory.
 *
 * In container, set env THREAT_SRC=/app/src (see docker-compose.yml).
 * Locally (CLI/web-server), it falls back to ../../src relative to this file.
 */

spl_autoload_register(function (string $class): void {
    $prefix  = 'rafalmasiarek\\Threat\\';
    $baseDir = getenv('THREAT_SRC');
    if (!$baseDir) {
        // when running outside of Docker, assume package root: examples/../../src
        $baseDir = realpath(__DIR__ . '/../../src') ?: (__DIR__ . '/../../src');
    }
    $baseDir = rtrim($baseDir, '/\\') . '/';

    $len = strlen($prefix);
    if (strncmp($prefix, $class, $len) !== 0) {
        return; // not our namespace
    }
    $rel  = substr($class, $len);
    $file = $baseDir . str_replace('\\', '/', $rel) . '.php';
    if (is_file($file)) {
        require $file;
    }
});
