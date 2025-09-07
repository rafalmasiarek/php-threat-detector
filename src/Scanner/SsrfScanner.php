<?php

declare(strict_types=1);

namespace rafalmasiarek\Threat\Scanner;

use rafalmasiarek\Threat\Contracts\ScannerInterface;

/**
 * Class SsrfScanner
 *
 * Detects SSRF indicators (localhost, RFC1918 networks).
 */
final class SsrfScanner implements ScannerInterface
{
    public function category(): string
    {
        return 'SSRF';
    }

    public function scan(string $normalized): array
    {
        // 1) No scheme delimiter? Definitely not a URL → no hits.
        if (strpos($normalized, '://') === false) {
            return [];
        }

        // 2) Extract candidate URLs (avoid greedy match; keep it simple and robust)
        //    Matches e.g. http://127.0.0.1, https://localhost:8443/, file:///etc/passwd
        $urlRegex = '/(?i)\b(?:https?|ftp|file):\/\/[^\s<>"\'()]+/u';
        if (!preg_match_all($urlRegex, $normalized, $m)) {
            return [];
        }

        $hits  = [];
        foreach ($m[0] as $url) {
            $p = @parse_url($url);
            if (!$p || empty($p['host'])) {
                continue;
            }

            // Normalize host (strip IPv6 brackets)
            $host = trim((string)$p['host'], '[]');

            // localhost / loopback
            if (strcasecmp($host, 'localhost') === 0) {
                $hits[] = 'LOCALHOST_URL';
                continue;
            }
            if (filter_var($host, FILTER_VALIDATE_IP)) {
                // IPv4 loopback / ANY / IPv6 loopback
                if ($host === '127.0.0.1' || $host === '0.0.0.0' || $host === '::1') {
                    $hits[] = 'LOCALHOST_URL';
                    continue;
                }
                // RFC1918 private ranges
                if (preg_match(
                    '/^(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})$/',
                    $host
                )) {
                    $hits[] = 'RFC1918_URL';
                }
            }
        }

        return array_values(array_unique($hits));
    }
}
