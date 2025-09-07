<?php

declare(strict_types=1);

namespace rafalmasiarek\Threat\Contracts;

/**
 * Interface ScannerInterface
 *
 * Represents a single-category scanner (e.g., XSS, SQLI).
 * Implementations must be stateless and fast.
 */
interface ScannerInterface
{
    /**
     * Get the category name this scanner represents (e.g., 'XSS', 'SQLI').
     *
     * @return string Category name
     */
    public function category(): string;

    /**
     * Scan normalized input and return unique hit codes.
     *
     * @param string $normalized Normalized input (HTML entities and URL-encodings already decoded).
     * @return array<int,string> List of hit codes (empty when no hits).
     */
    public function scan(string $normalized): array;
}
