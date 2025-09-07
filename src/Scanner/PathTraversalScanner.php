<?php

declare(strict_types=1);

namespace rafalmasiarek\Threat\Scanner;

use rafalmasiarek\Threat\Contracts\ScannerInterface;

/**
 * Class PathTraversalScanner
 *
 * Detects path traversal and file wrapper indicators.
 */
final class PathTraversalScanner implements ScannerInterface
{
    public function category(): string
    {
        return 'PATH_TRAVERSAL';
    }

    public function scan(string $normalized): array
    {
        $patterns = [
            '/(?:^|[^\w])(?:\.\.\/|\.{2}\\\\)/u' => 'DOT_DOT',
            '/%2e%2e%2f|%2e%2e\//iu' => 'ENC_DOT_DOT',
            '/(?:^|[("\'\s=]))(?:php|data|expect|zip|phar):\/\//i' => 'WRAPPER',
            '/(?:^|[("\'\s=]))file:\/\/\//i' => 'FILE_WRAPPER',
        ];

        $hits = [];
        foreach ($patterns as $re => $code) {
            if (@preg_match($re, $normalized)) { // @ to avoid noisy warnings, we control the patterns
                if (preg_match($re, $normalized)) {
                    $hits[] = $code;
                }
            }
        }
        return $hits;
    }
}
