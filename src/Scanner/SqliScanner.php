<?php

declare(strict_types=1);

namespace rafalmasiarek\Threat\Scanner;

use rafalmasiarek\Threat\Contracts\ScannerInterface;

/**
 * Class SqliScanner
 *
 * Detects common SQL injection patterns.
 */
final class SqliScanner implements ScannerInterface
{
    public function category(): string
    {
        return 'SQLI';
    }

    public function scan(string $normalized): array
    {
        $patterns = [
            "/(?i)(?:'|\")\s*or\s*(?:'|\")?\s*1\s*(?:'|\")?\s*=\s*(?:'|\")?\s*1\s*(?:'|\")?/"
            => 'BOOLEAN_OR_1EQ1',
            '/(?i)\bUNION\b\s+\/\*?\s*\*\/?\s*\bSELECT\b\s+(?:[\w\W]{1,80}?)(?:\bFROM\b|\(|,)/'
            => 'UNION_SELECT',
            '/(?i)\bSLEEP\s*\(\s*\d+\s*\)/' => 'TIME_DELAY_SLEEP',
            '/(?i)\bBENCHMARK\s*\(\s*\d+,/' => 'TIME_DELAY_BENCHMARK',
            '/(?i)\bINFORMATION_SCHEMA\b/' => 'INFO_SCHEMA',
            '/(?i)\bLOAD_FILE\s*\(/' => 'LOAD_FILE',
            '/(?i)\bINTO\s+OUTFILE\b/' => 'INTO_OUTFILE',
            '/(?i)\bxp_cmdshell\b/' => 'MSSQL_XP_CMDSHELL',
            '/(?i)order\s+by\s+\d{3,}\b/' => 'ORDER_BY_LARGE',
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
