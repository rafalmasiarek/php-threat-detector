<?php

declare(strict_types=1);

namespace rafalmasiarek\Threat\Scanner;

use rafalmasiarek\Threat\Contracts\ScannerInterface;

/**
 * Class SerializationScanner
 *
 * Detects PHP serialization patterns.
 */
final class SerializationScanner implements ScannerInterface
{
    public function category(): string
    {
        return 'SERIALIZATION';
    }

    public function scan(string $normalized): array
    {
        $patterns = [
            '/(?<![A-Za-z0-9_])a:\d+:\{[^}]*\}/u' => 'SERIAL_ARRAY',
            '/(?<![A-Za-z0-9_])s:\d+:\"[^\"]*\";/u' => 'SERIAL_STRING',
            '/(?<![A-Za-z0-9_])O:\d+:\"[A-Za-z0-9_\\]+\":\d+:\{[^}]*\}/u' => 'SERIAL_OBJECT',
        ];

        $hits = [];
        foreach ($patterns as $re => $code) {
            if (preg_match($re, $normalized)) {
                $hits[] = $code;
            }
        }
        return $hits;
    }
}
