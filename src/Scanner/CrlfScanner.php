<?php

declare(strict_types=1);

namespace rafalmasiarek\Threat\Scanner;

use rafalmasiarek\Threat\Contracts\ScannerInterface;

/**
 * Class CrlfScanner
 *
 * Detects CRLF/header injection attempts.
 */
final class CrlfScanner implements ScannerInterface
{
    public function category(): string
    {
        return 'CRLF';
    }

    public function scan(string $normalized): array
    {
        if (preg_match(
            "/(?:\r\n|%0d%0a)[ \t]*[A-Za-z0-9-]{2,}\s*:\s*[^\r\n]+(?:\r\n|%0d%0a)/u",
            $normalized
        )) {
            return ['HEADER_INJECT'];
        }
        return [];
    }
}
