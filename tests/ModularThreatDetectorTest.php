<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use rafalmasiarek\Threat\Core\ThreatDetector;
use rafalmasiarek\Threat\Core\ScoringPolicy;
use rafalmasiarek\Threat\Core\Thresholds;

/**
 * Basic smoke tests for the detector.
 */
final class ModularThreatDetectorTest extends TestCase
{
    public function testXssIsDetected(): void
    {
        $detector = ThreatDetector::default(ScoringPolicy::withDefaults()->withThreshold('LOW'));
        $res = $detector->scanString('<script>alert(1)</script>');
        $this->assertTrue($res->suspect);
        $this->assertArrayHasKey('XSS', $res->hits);
        $this->assertGreaterThan(0.0, $res->score);
    }

    public function testBenignIsNotSuspectAtMedium(): void
    {
        $detector = ThreatDetector::default(ScoringPolicy::withDefaults()->withThreshold(Thresholds::MEDIUM));
        $res = $detector->scanString('Hello world & welcome');
        $this->assertFalse($res->suspect);
        $this->assertSame([], $res->hits);
        $this->assertSame(0.0, $res->score);
    }
}
