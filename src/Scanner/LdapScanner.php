<?php

declare(strict_types=1);

namespace rafalmasiarek\Threat\Scanner;

use rafalmasiarek\Threat\Contracts\ScannerInterface;

/**
 * Class LdapScanner
 *
 * Detects LDAP filter injection artifacts.
 */
final class LdapScanner implements ScannerInterface
{
    public function category(): string
    {
        return 'LDAP';
    }

    public function scan(string $normalized): array
    {
        $patterns = [
            '/\(\s*\|(?:\s*\([^)]+\)\s*)+\)/u' => 'LDAP_OR',
            '/\(\s*[a-z0-9_-]+\s*=\s*\*\s*\)/iu' => 'LDAP_WILDCARD',
            '/\x00/u' => 'LDAP_NULL_BYTE',
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
