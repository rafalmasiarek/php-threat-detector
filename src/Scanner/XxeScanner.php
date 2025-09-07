<?php

declare(strict_types=1);

namespace rafalmasiarek\Threat\Scanner;

use rafalmasiarek\Threat\Contracts\ScannerInterface;

/**
 * Class XxeScanner
 *
 * Detects XML External Entity (XXE) indicators.
 */
final class XxeScanner implements ScannerInterface
{
    public function category(): string
    {
        return 'XXE';
    }

    public function scan(string $normalized): array
    {
        $patterns = [
            '/<!DOCTYPE\s+[a-z0-9:_-]+/iu' => 'DOCTYPE',
            '/<!ENTITY\s+[a-z0-9:_-]+\s+(?:SYSTEM|PUBLIC)\b/iu' => 'ENTITY',
            '/\bSYSTEM\b[^>]{0,100}\b(?:https?|file|ftp):/iu' => 'SYSTEM_EXTERNAL',
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
