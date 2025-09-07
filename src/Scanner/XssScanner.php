<?php

declare(strict_types=1);

namespace rafalmasiarek\Threat\Scanner;

use rafalmasiarek\Threat\Contracts\ScannerInterface;

/**
 * Class XssScanner
 *
 * Detects common indicators of Cross-Site Scripting (XSS).
 */
final class XssScanner implements ScannerInterface
{
    public function category(): string
    {
        return 'XSS';
    }

    public function scan(string $normalized): array
    {
        $patterns = [
            // Real HTML tags
            '/<\s*script\b[^>]*>/iu'                         => 'TAG_SCRIPT',
            '/<\s*iframe\b[^>]*>/iu'                         => 'TAG_IFRAME',
            '/<\s*svg\b[^>]*>/iu'                            => 'TAG_SVG',
            '/<\s*link\b[^>]*>/iu'                           => 'TAG_LINK',
            '/<\s*base\b[^>]*>/iu'                           => 'TAG_BASE',
            '/(?<=^|[(("\x27\s=])javascript\s*:/iu'          => 'JS_URI',
            '/(?<![a-z])expression\s*\(/iu'                  => 'CSS_EXPRESSION',
            '/(?<=^|[(("\x27\s=])data\s*:\s*text\/html\b/iu' => 'DATA_HTML',
            '/<\s*img\b[^>]*\bon[a-z0-9_-]+\s*=/iu'          => 'IMG_EVENT',
            '/\bjavascript:\s*/iu'                           => 'JAVASCRIPT_PROTOCOL',
            '/\bdata:\s*text\/html\b/iu'                     => 'DATA_HTML_PROTOCOL',
            '/<\s*\/?\s*[a-z][^>]*>/iu'                      => 'HTML_TAG',
            '/&\s*#\s*x?0*\s6[0-9a-f]+\s*;/iu'               => 'HTML_HEX_ENTITY',
            '/<[a-z][^>]*\s(on[a-z0-9_-]+)\s*=\s*(?:"[^"]*"|\x27[^\x27]*\x27|[^\s>]+)/iu'
            => 'EVENT_HANDLER_ATTR',
            '/<[a-z][^>]*\sstyle\s*=\s*(?:"[^"]*"|\x27[^\x27]*\x27|[^\s>]+)/iu'
            => 'INLINE_STYLE',
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
