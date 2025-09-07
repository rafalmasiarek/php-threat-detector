<?php

declare(strict_types=1);

namespace rafalmasiarek\Threat\Core;

use rafalmasiarek\Threat\Contracts\ScannerInterface;
use rafalmasiarek\Threat\Scanner;

/**
 * Class ThreatDetector
 *
 * Orchestrates scanners, normalization and weighted scoring.
 */
final class ThreatDetector
{
    /** @var int Hard cap to avoid pathological inputs (DoS on huge strings). */
    private const MAX_LEN = 65536;

    /** @var list<ScannerInterface> Ordered scanner instances */
    private array $scanners;

    /** @var ScoringPolicy Active scoring policy */
    private ScoringPolicy $policy;

    /**
     * @param list<ScannerInterface> $scanners List of scanners to run
     * @param ScoringPolicy          $policy   Scoring policy
     */
    public function __construct(array $scanners, ScoringPolicy $policy)
    {
        $this->scanners = $scanners;
        $this->policy   = $policy;
    }

    /**
     * Build a detector with the default scanner set and a policy (default weights + MEDIUM threshold).
     *
     * @param ScoringPolicy|null $policy Optional policy
     * @return self
     */
    public static function default(?ScoringPolicy $policy = null): self
    {
        $policy ??= ScoringPolicy::withDefaults();
        return new self([
            new Scanner\XssScanner(),
            new Scanner\SqliScanner(),
            new Scanner\CmdInjectionScanner(),
            new Scanner\PathTraversalScanner(),
            new Scanner\CrlfScanner(),
            new Scanner\SsrfScanner(),
            new Scanner\XxeScanner(),
            new Scanner\NoSqlScanner(),
            new Scanner\LdapScanner(),
            new Scanner\SerializationScanner(),
        ], $policy);
    }

    /**
     * Scan a raw string.
     *
     * @param string $input Raw input value
     * @return ThreatResult Immutable result object
     */
    public function scanString(string $input): ThreatResult
    {
        $norm = $this->normalize($input);
        $hits = [];

        foreach ($this->scanners as $scanner) {
            $codes = $scanner->scan($norm);
            if (!empty($codes)) {
                $hits[$scanner->category()] = array_values(array_unique($codes));
            }
        }

        // Weighted score across all categories
        $score = 0.0;
        foreach ($hits as $cat => $codes) {
            $score += $this->policy->weightFor($cat) * count($codes);
        }
        $suspect = $score >= $this->policy->threshold();

        return new ThreatResult($suspect, $score, $hits, $norm);
    }

    /**
     * Convenience method: scan and export as array.
     *
     * @param string $input Raw input value
     * @return array{suspect:bool,score:float,hits:array<string,array<int,string>>,norm:string}
     */
    public function scanToArray(string $input): array
    {
        return $this->scanString($input)->toArray();
    }

    /**
     * Normalize a string by limited HTML-entity & URL decoding, whitespace collapse, and trim.
     *
     * @param string $s Raw input
     * @return string Normalized input
     */
    private function normalize(string $s): string
    {
        $cur  = mb_substr($s, 0, self::MAX_LEN);
        $prev = null;

        for ($i = 0; $i < 3; $i++) {
            $cur = html_entity_decode($cur, ENT_QUOTES | ENT_HTML5, 'UTF-8');
            $tmp = $cur;
            try {
                $cur = urldecode($cur);
            } catch (\Throwable) {
                $cur = $tmp;
            }
            if ($cur === $prev) break;
            $prev = $cur;
        }

        $cur = preg_replace('/\s+/u', ' ', $cur);
        return trim($cur ?? '');
    }
}
