<?php

declare(strict_types=1);

namespace rafalmasiarek\Threat\Scanner;

use rafalmasiarek\Threat\Contracts\ScannerInterface;

/**
 * Class CmdInjectionScanner
 *
 * Detects shell/command injection indicators.
 */
final class CmdInjectionScanner implements ScannerInterface
{
    public function category(): string
    {
        return 'CMD_INJECTION';
    }

    public function scan(string $normalized): array
    {
        $patterns = [
            '/[`$]\([^)]*\)/u'                                              => 'SUBSHELL',
            '/(?<![\w])(?:\|\||&&|;)(?=\s|$)/u'                           => 'SHELL_OP',
            '/(?<![\w.-])(wget|curl|nc|bash|sh|powershell|cmd|tftp)(?:\.exe)?(?![\w.-])/iu'
            => 'SHELL_NAME',
            '/(?i)(?<![\w-])(rm\s+-rf|chmod\s+\d{3}|chown\s+\w+:\w+)(?![\w-])/' => 'DANGEROUS_CMD',
            '/\s>>?\s*[^\s><|;&]+/u'                                       => 'SHELL_REDIRECT',
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
