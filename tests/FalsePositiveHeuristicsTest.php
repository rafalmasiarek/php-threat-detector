<?php
declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use rafalmasiarek\Threat\Core\ThreatDetector;

final class FalsePositiveHeuristicsTest extends TestCase
{
    private ThreatDetector $det;

    protected function setUp(): void
    {
        $rul = __DIR__ . '/../dist/ruleset.rul';
        if (!is_file($rul)) {
            // Try to build from project root
            $json = __DIR__ . '/../rules/ruleset.json';
            $thc  = __DIR__ . '/../bin/threatc';
            if (is_file($json) && is_file($thc)) {
                @mkdir(dirname($rul), 0777, true);
                // build
                $cmd = sprintf('php %s build %s %s', escapeshellarg($thc), escapeshellarg($json), escapeshellarg($rul));
                exec($cmd, $o, $code);
            }
        }
        if (!is_file($rul)) {
            $this->markTestSkipped('ruleset.rul not available');
        }
        $this->det = ThreatDetector::fromRuleset($rul);
    }

    /**
     * @dataProvider benignProvider
     */
    public function test_benign_inputs_are_not_suspect(string $label, string $input): void
    {
        $res = $this->det->scanString($input);
        $this->assertFalse($res->suspect, sprintf('[%s] Hits=%s Score=%.2f', $label, json_encode($res->hits), $res->score));
    }

    public function benignProvider(): array
    {
        return [
            ['greeting', 'Hello world & have a nice day!'],
            ['union-wording', 'Union Select Committee Report'],
            ['info schema wording', 'The information schema is well documented.'],
            ['plain private ip mention', 'My laptop IP is 192.168.1.42'],
            ['ipv6 loopback mention', 'We pinged ::1 yesterday.'],
            ['onsale-like', 'Our brand: OnyxStyle (onsale=10%)'],
            ['path doc text', 'Use ../ to go up a directory in docs.'],
        ];
    }
}
