<?php

declare(strict_types=1);

namespace rafalmasiarek\Threat\Core;

/**
 * Class Thresholds
 *
 * Predefined float thresholds for suspicion decisions.
 */
final class Thresholds
{
    public const LOW    = 1.0;
    public const MEDIUM = 2.5;
    public const HIGH   = 5.0;

    /**
     * Resolve a string keyword into a float threshold.
     *
     * @param string $name 'LOW'|'MEDIUM'|'HIGH'
     * @return float The resolved threshold
     */
    public static function resolve(string $name): float
    {
        return match (strtoupper($name)) {
            'LOW'    => self::LOW,
            'MEDIUM' => self::MEDIUM,
            'HIGH'   => self::HIGH,
            default  => self::MEDIUM,
        };
    }
}
