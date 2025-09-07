<?php

declare(strict_types=1);

namespace rafalmasiarek\Threat\Middleware;

use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Http\Message\ResponseInterface;
use rafalmasiarek\Threat\Core\ThreatDetector;
use rafalmasiarek\Threat\Core\ScoringPolicy;
use rafalmasiarek\Threat\Core\Thresholds;

/**
 * Class ThreatDetectMiddleware
 *
 * PSR-15 middleware that scans selected parts of the request and attaches
 * a compact result as request attribute.
 *
 * Options:
 *  - threshold: 'LOW'|'MEDIUM'|'HIGH'|float (default: 'MEDIUM')
 *  - weights: array<string,float> per-category overrides
 *  - scan_query (bool)
 *  - scan_body (bool)
 *  - scan_headers (bool|array) true or list of header names
 *  - scan_cookies (bool)
 *  - attribute (string) request attribute name (default: 'threat.result')
 *  - set_header (bool) set 'X-Threat-Suspect: 1' when suspect (default: true)
 */
final class ThreatDetectMiddleware implements MiddlewareInterface
{
    /** @var array<string, mixed> */
    private array $config;

    /**
     * @param array<string, mixed> $config Middleware configuration
     */
    public function __construct(array $config = [])
    {
        $this->config = $config + [
            'threshold'    => 'MEDIUM',
            'weights'      => [],
            'scan_query'   => true,
            'scan_body'    => true,
            'scan_headers' => false,
            'scan_cookies' => false,
            'attribute'    => 'threat.result',
            'set_header'   => true,
        ];
    }

    /**
     * {@inheritDoc}
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $policy = ScoringPolicy::withDefaults()
            ->withThreshold($this->config['threshold']);

        foreach ((array)$this->config['weights'] as $cat => $w) {
            $policy = $policy->withWeight((string)$cat, (float)$w);
        }

        $detector = ThreatDetector::default($policy);
        $accScore = 0.0;
        $accHits  = [];

        if ($this->config['scan_query']) {
            $this->scanArray($request->getQueryParams(), $detector, $accScore, $accHits);
        }
        if ($this->config['scan_cookies']) {
            $this->scanArray($request->getCookieParams(), $detector, $accScore, $accHits);
        }
        if ($this->config['scan_headers']) {
            $headers = $request->getHeaders();
            if (is_array($this->config['scan_headers'])) {
                $wanted = array_change_key_case(array_flip($this->config['scan_headers']), CASE_LOWER);
                $headers = array_filter($headers, fn($k) => isset($wanted[strtolower($k)]), ARRAY_FILTER_USE_KEY);
            }
            $this->scanArray($headers, $detector, $accScore, $accHits);
        }
        if ($this->config['scan_body']) {
            $parsed = $request->getParsedBody();
            if (is_array($parsed)) {
                $this->scanArray($parsed, $detector, $accScore, $accHits);
            } elseif (is_string($parsed)) {
                $r = $detector->scanString($parsed);
                $accScore += $r->score;
                $this->mergeHits($accHits, $r->hits);
            } else {
                $body = (string)$request->getBody();
                if ($body !== '') {
                    $r = $detector->scanString($body);
                    $accScore += $r->score;
                    $this->mergeHits($accHits, $r->hits);
                }
            }
        }

        $suspect = $accScore >= $policy->threshold();

        $result = [
            'suspect' => $suspect,
            'score'   => $accScore,
            'hits'    => $accHits,
        ];

        $request  = $request->withAttribute((string)$this->config['attribute'], $result);
        $response = $handler->handle($request);

        if (!empty($this->config['set_header']) && $suspect && !$response->hasHeader('X-Threat-Suspect')) {
            $response = $response->withHeader('X-Threat-Suspect', '1');
        }

        return $response;
    }

    /**
     * Scan nested arrays and accumulate score/hits.
     *
     * @param array<string,mixed>               $arr
     * @param ThreatDetector                    $detector
     * @param float                             $accScore (by-ref)
     * @param array<string, array<int,string>>  $accHits  (by-ref)
     * @return void
     */
    private function scanArray(array $arr, ThreatDetector $detector, float &$accScore, array &$accHits): void
    {
        $it = new \RecursiveIteratorIterator(new \RecursiveArrayIterator($arr));
        foreach ($it as $v) {
            if (!is_scalar($v)) continue;
            $r = $detector->scanString((string)$v);
            $accScore += $r->score;
            $this->mergeHits($accHits, $r->hits);
        }
    }

    /**
     * Merge hit maps (category => codes[]) in-place.
     *
     * @param array<string, array<int,string>> $into
     * @param array<string, array<int,string>> $from
     * @return void
     */
    private function mergeHits(array &$into, array $from): void
    {
        foreach ($from as $k => $list) {
            $into[$k] = array_values(array_unique(array_merge($into[$k] ?? [], $list)));
        }
    }
}
