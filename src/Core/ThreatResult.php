<?php

declare(strict_types=1);

namespace rafalmasiarek\Threat\Core;

/**
 * Class ThreatResult
 *
 * Immutable result of a scan operation.
 */
final class ThreatResult
{
    /** @var bool Whether the input meets or exceeds the active threshold */
    public bool $suspect;

    /** @var float Weighted float score across categories */
    public float $score;

    /** @var array<string, array<int,string>> Map of category => list of hit codes */
    public array $hits;

    /** @var string Normalized input string used for scanning */
    public string $norm;

    /**
     * @param bool                                   $suspect
     * @param float                                  $score
     * @param array<string, array<int,string>>       $hits
     * @param string                                 $norm
     */
    public function __construct(bool $suspect, float $score, array $hits, string $norm)
    {
        $this->suspect = $suspect;
        $this->score   = $score;
        $this->hits    = $hits;
        $this->norm    = $norm;
    }

    /**
     * Export the result to a well-typed array (handy for logs).
     *
     * @return array{suspect:bool,score:float,hits:array<string,array<int,string>>,norm:string}
     */
    public function toArray(): array
    {
        return [
            'suspect' => $this->suspect,
            'score'   => $this->score,
            'hits'    => $this->hits,
            'norm'    => $this->norm,
        ];
    }
}
