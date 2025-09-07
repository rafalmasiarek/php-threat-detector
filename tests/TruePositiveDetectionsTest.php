<?php
declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use rafalmasiarek\Threat\Core\ThreatDetector;

final class TruePositiveDetectionsTest extends TestCase
{
    private ThreatDetector $det;

    protected function setUp(): void
    {
        $rul = __DIR__ . '/../dist/ruleset.rul';
        if (!is_file($rul)) {
            $json = __DIR__ . '/../rules/ruleset.json';
            $thc  = __DIR__ . '/../bin/threatc';
            if (is_file($json) && is_file($thc)) {
                @mkdir(dirname($rul), 0777, true);
                $cmd = sprintf('php %s build %s %s', escapeshellarg($thc), escapeshellarg($json), escapeshellarg($rul));
                exec($cmd, $o, $code);
            }
        }
        if (!is_file($rul)) {
            $this->markTestSkipped('ruleset.rul not available');
        }
        $this->det = ThreatDetector::fromRuleset($rul);
    }

    /** @dataProvider xssProvider */
    public function test_xss(string $payload): void
    {
        $r = $this->det->scanString($payload);
        $this->assertArrayHasKey('XSS', (array)$r->hits);
        $this->assertTrue($r->suspect);
    }

    public function xssProvider(): array
    {
        return [
            ['<script>alert(1)</script>'],
            ['<img src=x onerror=alert(1)>'],
            ['<a href="javascript:alert(1)">x</a>'],
            ['<div style="x:expression(alert(1))">x</div>'],
            ['<svg onload=alert(1)></svg>'],
        ];
    }

    /** @dataProvider sqliProvider */
    public function test_sqli(string $payload): void
    {
        $r = $this->det->scanString($payload);
        $this->assertArrayHasKey('SQLI', (array)$r->hits);
        $this->assertTrue($r->suspect);
    }

    public function sqliProvider(): array
    {
        return [
            ["' or '1'='1"],
            ['UNION SELECT password FROM users'],
            ['SLEEP(5)'],
            ['BENCHMARK(1000000, sha1(1))'],
            ['INFORMATION_SCHEMA.TABLES'],
        ];
    }

    /** @dataProvider cmdProvider */
    public function test_cmd(string $payload): void
    {
        $r = $this->det->scanString($payload);
        $this->assertArrayHasKey('CMD_INJECTION', (array)$r->hits);
        $this->assertTrue($r->suspect);
    }

    public function cmdProvider(): array
    {
        return [
            ['`id`'],
            ['$(id)'],
            ['rm -rf /; cat /etc/passwd'],
            ['curl 127.0.0.1/shell.sh'],
            ['wget 192.168.1.10/file'],
        ];
    }

    /** @dataProvider ssrfProvider */
    public function test_ssrf(string $payload): void
    {
        $r = $this->det->scanString($payload);
        $this->assertArrayHasKey('SSRF', (array)$r->hits);
        $this->assertTrue($r->suspect);
    }

    public function ssrfProvider(): array
    {
        return [
            ['http://127.0.0.1/admin'],
            ['https://192.168.1.10:8443/'],
            ['ftp://10.0.0.5/readme'],
            ['file:///etc/passwd'],
        ];
    }
}
