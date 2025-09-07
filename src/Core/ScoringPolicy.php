<?php

declare(strict_types=1);

namespace rafalmasiarek\Threat\Core;

/**
 * Class ScoringPolicy
 *
 * Holds category weights and global threshold for suspicion decisions.
 */
final class ScoringPolicy
{
    /** @var array<string,float> */
    private array $weights;

    /** @var float */
    private float $threshold;

    /**
     * @param array<string,float> $weights  Per-category weights
     * @param float               $threshold Float threshold for 'suspect'
     */
    public function __construct(array $weights, float $threshold)
    {
        $this->weights   = $weights;
        $this->threshold = $threshold;
    }

    /**
     * Create policy with baseline weights and MEDIUM threshold.
     *
     * @return self
     */
    public static function withDefaults(): self
    {
        return new self([
            'XSS'            => 1.5,
            'SQLI'           => 2.0,
            'CMD_INJECTION'  => 2.5,
            'PATH_TRAVERSAL' => 1.5,
            'CRLF'           => 1.0,
            'SSRF'           => 2.0,
            'XXE'            => 1.5,
            'NOSQL'          => 1.5,
            'LDAP'           => 1.0,
            'SERIALIZATION'  => 1.0,
        ], Thresholds::MEDIUM);
    }

    /**
     * Return a cloned policy with an overridden weight for a category.
     *
     * @param string $category Category name
     * @param float  $weight   Weight value
     * @return self New policy instance
     */
    public function withWeight(string $category, float $weight): self
    {
        $clone = clone $this;
        $clone->weights[$category] = $weight;
        return $clone;
    }

    /**
     * Return a cloned policy with a new threshold.
     *
     * @param float|string $threshold Float or 'LOW'|'MEDIUM'|'HIGH'
     * @return self New policy instance
     */
    public function withThreshold(float|string $threshold): self
    {
        $clone = clone $this;
        $clone->threshold = is_string($threshold)
            ? Thresholds::resolve($threshold)
            : (float)$threshold;
        return $clone;
    }

    /**
     * Get all weights.
     *
     * @return array<string,float>
     */
    public function weights(): array
    {
        return $this->weights;
    }

    /**
     * Get weight for a specific category.
     *
     * @param string $category Category name
     * @return float Weight value
     */
    public function weightFor(string $category): float
    {
        return $this->weights[$category] ?? 1.0;
    }

    /**
     * Get the active threshold.
     *
     * @return float
     */
    public function threshold(): float
    {
        return $this->threshold;
    }
}
