<?php

declare(strict_types=1);

namespace rafalmasiarek\Threat\Scanner;

use rafalmasiarek\Threat\Contracts\ScannerInterface;

/**
 * Class NoSqlScanner
 *
 * Detects Mongo-like operator usage in input.
 */
final class NoSqlScanner implements ScannerInterface
{
    public function category(): string
    {
        return 'NOSQL';
    }

    public function scan(string $normalized): array
    {
        $patterns = [
            '/\{\s*\"(?:\$where|\$ne|\$gt|\$lt|\$regex)\"\s*:\s*[^}]+}/u' => 'MONGO_OPERATOR_JSON',
            '/(?<![a-z0-9_])\$(where|ne|gt|lt|regex)\b(?![a-z0-9_])/iu' => 'MONGO_OPERATOR',
            '/\bdb\.[a-z0-9_]+\.[a-z0-9_]+\s*\(/iu' => 'MONGO_DB_CALL',
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
