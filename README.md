# php-threat-detector


[![Latest Version](https://img.shields.io/packagist/v/rafalmasiarek/threat-detector.svg)](https://packagist.org/packages/rafalmasiarek/threat-detector)
[![License](https://img.shields.io/github/license/rafalmasiarek/threat-detector)](LICENSE)
![PHP](https://img.shields.io/badge/PHP-%5E8.1-blue)







Heuristic, **modular** threat detection (signal-only) with **weighted float scoring**, **predefined thresholds**, and **PSR-15 middleware** for PSR-7 applications.

> ⚠️ This library is a *signal generator*. It **does not replace** proper validation/sanitization/escaping, CSP, prepared statements, etc.







## License

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

```text
The MIT License (MIT)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files, to deal in the Software
without restriction.

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.

Source: https://opensource.org/licenses/MIT
```


See [LICENSE](LICENSE) for full details.


## Authors

- Rafał Masiarek | [website](https://masiarek.pl) | [github](https://github.com/rafalmasiarek)




## Features

- 🧩 **Modular scanners** — each category (XSS, SQLi, SSRF, …) in a separate class.
- ⚖️ **Weighted float scoring** — per-category weights; combine multiple signals.
- 🎚️ **Predefined thresholds** — `LOW`, `MEDIUM`, `HIGH` (or custom floats).
- 🧵 **PSR-15 middleware** — scan query, body, headers, cookies; annotate request; optional header `X-Threat-Suspect`.
- 📝 **phpDocs & comments** — production-friendly code with clear docs.
- ✅ **Unit tests** — a couple of quick checks to get you started.
- 📂 **Examples** — basic HTML form + PSR-15 middleware demo.

---

## Requirements

- PHP **8.1+**
- ext-mbstring

---

## Installation

Using Composer:

```bash
composer require rafalmasiarek/threat-detector
```

If you are using this repository locally (path repo):

```bash
composer config repositories.threat-detector path ./threat-detector
composer require rafalmasiarek/threat-detector:dev-main
```

---

## Quick Start (Core)

```php
use rafalmasiarek\Threat\Core\ThreatDetector;
use rafalmasiarek\Threat\Core\ScoringPolicy;
use rafalmasiarek\Threat\Core\Thresholds;

// Create a policy with default weights and MEDIUM threshold
$policy = ScoringPolicy::withDefaults()
    ->withThreshold(Thresholds::MEDIUM)  // or 'LOW' | 'HIGH' | 3.5 (float)
    ->withWeight('SQLI', 2.25);          // optional: override category weights

$detector = ThreatDetector::default($policy);

// Scan a string
$input = "<script>alert(1)</script>";
$result = $detector->scanString($input);

var_dump($result->suspect); // bool
var_dump($result->score);   // float
var_dump($result->hits);    // array{category => list<string>}
var_dump($result->norm);    // normalized input
```

Example output:

```php
bool(true)
float(3)
array(1) {
  ["XSS"]=>
  array(2) {
    [0]=> string(10) "TAG_SCRIPT"
    [1]=> string(9)  "HTML_TAGS"
  }
}
string(23) "<script>alert(1)</script>"
```

---

## Quick Start (PSR-15 Middleware)

```php
use rafalmasiarek\Threat\Middleware\ThreatDetectMiddleware;

$middleware = new ThreatDetectMiddleware([
    'threshold'    => 'MEDIUM',          // 'LOW' | 'MEDIUM' | 'HIGH' | float
    'weights'      => ['SQLI' => 2.1],   // optional overrides
    'scan_query'   => true,
    'scan_body'    => true,
    'scan_headers' => false,             // true or array of headers to scan
    'scan_cookies' => false,
    'attribute'    => 'threat.result',   // request attribute name
    'set_header'   => true,              // add X-Threat-Suspect: 1 when suspect
]);

// Add to your PSR-15 stack (Slim/Mezzio/etc.)
$result = $request->getAttribute('threat.result'); 
```

Example result:

```php
[
  'suspect' => true,
  'score'   => 3.5,
  'hits'    => ['XSS' => ['TAG_SCRIPT','HTML_TAGS']],
]
```

---

## Scoring

- **Weights**: per category (e.g., `SQLI=2.0`, `CMD_INJECTION=2.5`, `CRLF=1.0`).
- **Score formula**:  
  ```
  score = Σ ( weight(category) × unique_hits(category) )
  ```
- **Threshold**: request is **suspect** when `score ≥ threshold`.

### Predefined thresholds

| Name   | Value | Sensitivity        |
|--------|-------|--------------------|
| LOW    | 1.0   | Very sensitive     |
| MEDIUM | 2.5   | Balanced (default) |
| HIGH   | 5.0   | Strict             |

### Examples

- `<script>alert(1)</script>`  
  Hits: `XSS=[TAG_SCRIPT, HTML_TAGS]`  
  Score: `1.5 × 2 = 3.0` → suspect at `MEDIUM`

- `UNION SELECT password FROM users`  
  Hits: `SQLI=[UNION_SELECT]`  
  Score: `2.0 × 1 = 2.0` → not suspect at `MEDIUM`, suspect at `LOW`

---

## Categories & Scanners

- **XSS** — inline event handlers, `<script>`, `javascript:` URIs.
- **SQLI** — `UNION SELECT`, `SLEEP()`, `INFORMATION_SCHEMA`, etc.
- **CMD_INJECTION** — subshells, `;`, `&&`, `wget/curl`, redirects.
- **PATH_TRAVERSAL** — `../`, URL-encoded traversal, `file://`, wrappers.
- **CRLF** — header injection sequences.
- **SSRF** — URLs to `localhost`, `127.0.0.1`, `RFC1918` ranges.
- **XXE** — `<!DOCTYPE>`, `<!ENTITY>`, external SYSTEM.
- **NOSQL** — Mongo-like operators `$where`, `$regex`.
- **LDAP** — wildcards, null bytes.
- **SERIALIZATION** — PHP serialized payload patterns.

---

## Integration Ideas

- Add to Slim/Mezzio pipeline as PSR-15 middleware.  
- Run against form input before sending mail (contact forms).  
- Log suspect inputs into a security audit trail.  
- Flag suspicious requests in rate-limiting / WAF logic.  

---

## Tests & Examples

- PHPUnit tests included (`tests/`):
  - `TruePositiveDetectionsTest.php`
  - `FalsePositiveHeuristicsTest.php`
- Example apps in `examples/`:
  - `basic/` (HTML form demo)
  - `psr15/` (middleware demo)

Run tests:

```bash
./vendor/bin/phpunit --colors=always
```

---

## Security Notice

This library generates **signals only**.  
Always combine with:
- Prepared statements for SQL queries
- Proper HTML escaping and CSP
- Strong input validation

---

## Folder Structure

```
src/
  Contracts/ScannerInterface.php
  Core/{ThreatDetector.php, ThreatResult.php, ScoringPolicy.php, Thresholds.php}
  Scanner/{XssScanner.php, SqliScanner.php, CmdInjectionScanner.php, PathTraversalScanner.php, CrlfScanner.php, SsrfScanner.php, XxeScanner.php, NoSqlScanner.php, LdapScanner.php, SerializationScanner.php}
  Middleware/ThreatDetectMiddleware.php
tests/
  ModularThreatDetectorTest.php
examples/
  basic/
  psr15/
```



## Index

### Classes

- [`ScoringPolicy`](#scoringpolicy) — `rafalmasiarek\Threat\Core`
- [`ThreatDetector`](#threatdetector) — `rafalmasiarek\Threat\Core`
- [`ThreatResult`](#threatresult) — `rafalmasiarek\Threat\Core`
- [`Thresholds`](#thresholds) — `rafalmasiarek\Threat\Core`
- [`ThreatDetectMiddleware`](#threatdetectmiddleware) — `rafalmasiarek\Threat\Middleware`
- [`CmdInjectionScanner`](#cmdinjectionscanner) — `rafalmasiarek\Threat\Scanner`
- [`CrlfScanner`](#crlfscanner) — `rafalmasiarek\Threat\Scanner`
- [`LdapScanner`](#ldapscanner) — `rafalmasiarek\Threat\Scanner`
- [`NoSqlScanner`](#nosqlscanner) — `rafalmasiarek\Threat\Scanner`
- [`PathTraversalScanner`](#pathtraversalscanner) — `rafalmasiarek\Threat\Scanner`
- [`SerializationScanner`](#serializationscanner) — `rafalmasiarek\Threat\Scanner`
- [`SqliScanner`](#sqliscanner) — `rafalmasiarek\Threat\Scanner`
- [`SsrfScanner`](#ssrfscanner) — `rafalmasiarek\Threat\Scanner`
- [`XssScanner`](#xssscanner) — `rafalmasiarek\Threat\Scanner`
- [`XxeScanner`](#xxescanner) — `rafalmasiarek\Threat\Scanner`

### Interfaces

- [`ScannerInterface`](#scannerinterface) — `rafalmasiarek\Threat\Contracts`

## `ScannerInterface`

*interface* — `rafalmasiarek\Threat\Contracts\ScannerInterface` · [source](https://github.com/rafalmasiarek/php-threat-detector/blob/main/src/Contracts/ScannerInterface.php#L13)

Interface ScannerInterface Represents a single-category scanner (e.g., XSS, SQLI). Implementations must be stateless and fast.

| Method | Visibility | Returns | Summary |
|---|---|---|---|
| [`category()`](#scannerinterface-category) | public | `string` | Get the category name this scanner represents (e.g., 'XSS', 'SQLI'). |
| [`scan()`](#scannerinterface-scan) | public | `array<int, string>` | Scan normalized input and return unique hit codes. |

<details>
<summary><code>category()</code></summary>

#### `ScannerInterface category()`

[source](https://github.com/rafalmasiarek/php-threat-detector/blob/main/src/Contracts/ScannerInterface.php#L20)

```php
public function category(): string
```

Get the category name this scanner represents (e.g., 'XSS', 'SQLI').

**Returns:** `string` — Category name

</details>

<details>
<summary><code>scan()</code></summary>

#### `ScannerInterface scan()`

[source](https://github.com/rafalmasiarek/php-threat-detector/blob/main/src/Contracts/ScannerInterface.php#L28)

```php
public function scan(string $normalized): array
```

Scan normalized input and return unique hit codes.

| Param | Type | Description |
|---|---|---|
| `$normalized` | `string` | Normalized input (HTML entities and URL-encodings already decoded). |

**Returns:** `array<int, string>` — List of hit codes (empty when no hits).

</details>

## `ScoringPolicy`

*final class* — `rafalmasiarek\Threat\Core\ScoringPolicy` · [source](https://github.com/rafalmasiarek/php-threat-detector/blob/main/src/Core/ScoringPolicy.php#L12)

Class ScoringPolicy Holds category weights and global threshold for suspicion decisions.

| Property | Type | Visibility | Description |
|---|---|---|---|
| `$weights` | `array<string, float>` | private | — |
| `$threshold` | `float` | private | — |

| Method | Visibility | Returns | Summary |
|---|---|---|---|
| [`__construct()`](#scoringpolicy-__construct) | public | — | — |
| [`withDefaults()`](#scoringpolicy-withdefaults) | public static | `self` | Create policy with baseline weights and MEDIUM threshold. |
| [`withWeight()`](#scoringpolicy-withweight) | public | `self` | Return a cloned policy with an overridden weight for a category. |
| [`withThreshold()`](#scoringpolicy-withthreshold) | public | `self` | Return a cloned policy with a new threshold. |
| [`weights()`](#scoringpolicy-weights) | public | `array<string, float>` | Get all weights. |
| [`weightFor()`](#scoringpolicy-weightfor) | public | `float` | Get weight for a specific category. |
| [`threshold()`](#scoringpolicy-threshold) | public | `float` | Get the active threshold. |

<details>
<summary><code>__construct()</code></summary>

#### `ScoringPolicy __construct()`

[source](https://github.com/rafalmasiarek/php-threat-detector/blob/main/src/Core/ScoringPolicy.php#L24)

```php
public function __construct(array $weights, float $threshold)
```

| Param | Type | Description |
|---|---|---|
| `$weights` | `array<string, float>` | Per-category weights |
| `$threshold` | `float` | Float threshold for 'suspect' |

</details>

<details>
<summary><code>withDefaults()</code></summary>

#### `ScoringPolicy withDefaults()`

[source](https://github.com/rafalmasiarek/php-threat-detector/blob/main/src/Core/ScoringPolicy.php#L35)

```php
public static function withDefaults(): self
```

Create policy with baseline weights and MEDIUM threshold.

**Returns:** `self`

</details>

<details>
<summary><code>withWeight()</code></summary>

#### `ScoringPolicy withWeight()`

[source](https://github.com/rafalmasiarek/php-threat-detector/blob/main/src/Core/ScoringPolicy.php#L58)

```php
public function withWeight(string $category, float $weight): self
```

Return a cloned policy with an overridden weight for a category.

| Param | Type | Description |
|---|---|---|
| `$category` | `string` | Category name |
| `$weight` | `float` | Weight value |

**Returns:** `self` — New policy instance

</details>

<details>
<summary><code>withThreshold()</code></summary>

#### `ScoringPolicy withThreshold()`

[source](https://github.com/rafalmasiarek/php-threat-detector/blob/main/src/Core/ScoringPolicy.php#L71)

```php
public function withThreshold(float|string $threshold): self
```

Return a cloned policy with a new threshold.

| Param | Type | Description |
|---|---|---|
| `$threshold` | `float\|string` | Float or 'LOW'\|'MEDIUM'\|'HIGH' |

**Returns:** `self` — New policy instance

</details>

<details>
<summary><code>weights()</code></summary>

#### `ScoringPolicy weights()`

[source](https://github.com/rafalmasiarek/php-threat-detector/blob/main/src/Core/ScoringPolicy.php#L85)

```php
public function weights(): array
```

Get all weights.

**Returns:** `array<string, float>`

</details>

<details>
<summary><code>weightFor()</code></summary>

#### `ScoringPolicy weightFor()`

[source](https://github.com/rafalmasiarek/php-threat-detector/blob/main/src/Core/ScoringPolicy.php#L96)

```php
public function weightFor(string $category): float
```

Get weight for a specific category.

| Param | Type | Description |
|---|---|---|
| `$category` | `string` | Category name |

**Returns:** `float` — Weight value

</details>

<details>
<summary><code>threshold()</code></summary>

#### `ScoringPolicy threshold()`

[source](https://github.com/rafalmasiarek/php-threat-detector/blob/main/src/Core/ScoringPolicy.php#L106)

```php
public function threshold(): float
```

Get the active threshold.

**Returns:** `float`

</details>

## `ThreatDetector`

*final class* — `rafalmasiarek\Threat\Core\ThreatDetector` · [source](https://github.com/rafalmasiarek/php-threat-detector/blob/main/src/Core/ThreatDetector.php#L15)

Class ThreatDetector Orchestrates scanners, normalization and weighted scoring.

**Depends on:** [`ScoringPolicy`](#scoringpolicy)

| Property | Type | Visibility | Description |
|---|---|---|---|
| `$scanners` | `list<ScannerInterface>` | private | Ordered scanner instances |
| `$policy` | [`ScoringPolicy`](#scoringpolicy) | private | Active scoring policy |

| Method | Visibility | Returns | Summary |
|---|---|---|---|
| [`__construct()`](#threatdetector-__construct) | public | — | — |
| [`default()`](#threatdetector-default) | public static | `self` | Build a detector with the default scanner set and a policy (default weights + MEDIUM threshold). |
| [`scanString()`](#threatdetector-scanstring) | public | [`ThreatResult`](#threatresult) | Scan a raw string. |
| [`scanToArray()`](#threatdetector-scantoarray) | public | `array{suspect: bool, score: float, hits: array<string, array<int, string>>, norm: string}` | Convenience method: scan and export as array. |
| [`normalize()`](#threatdetector-normalize) | private | `string` | Normalize a string by limited HTML-entity & URL decoding, whitespace collapse, and trim. |

<details>
<summary><code>__construct()</code></summary>

#### `ThreatDetector __construct()`

[source](https://github.com/rafalmasiarek/php-threat-detector/blob/main/src/Core/ThreatDetector.php#L30)

```php
public function __construct(array $scanners, ScoringPolicy $policy)
```

| Param | Type | Description |
|---|---|---|
| `$scanners` | `list<ScannerInterface>` | List of scanners to run |
| `$policy` | [`ScoringPolicy`](#scoringpolicy) | Scoring policy |

</details>

<details>
<summary><code>default()</code></summary>

#### `ThreatDetector default()`

[source](https://github.com/rafalmasiarek/php-threat-detector/blob/main/src/Core/ThreatDetector.php#L42)

```php
public static function default(?ScoringPolicy $policy): self
```

Build a detector with the default scanner set and a policy (default weights + MEDIUM threshold).

| Param | Type | Description |
|---|---|---|
| `$policy` | `ScoringPolicy\|null` | Optional policy |

**Returns:** `self`

</details>

<details>
<summary><code>scanString()</code></summary>

#### `ThreatDetector scanString()`

[source](https://github.com/rafalmasiarek/php-threat-detector/blob/main/src/Core/ThreatDetector.php#L65)

```php
public function scanString(string $input): ThreatResult
```

Scan a raw string.

| Param | Type | Description |
|---|---|---|
| `$input` | `string` | Raw input value |

**Returns:** [`ThreatResult`](#threatresult) — Immutable result object

</details>

<details>
<summary><code>scanToArray()</code></summary>

#### `ThreatDetector scanToArray()`

[source](https://github.com/rafalmasiarek/php-threat-detector/blob/main/src/Core/ThreatDetector.php#L93)

```php
public function scanToArray(string $input): array
```

Convenience method: scan and export as array.

| Param | Type | Description |
|---|---|---|
| `$input` | `string` | Raw input value |

**Returns:** `array{suspect: bool, score: float, hits: array<string, array<int, string>>, norm: string}`

</details>

<details>
<summary><code>normalize()</code></summary>

#### `ThreatDetector normalize()`

[source](https://github.com/rafalmasiarek/php-threat-detector/blob/main/src/Core/ThreatDetector.php#L104)

```php
private function normalize(string $s): string
```

Normalize a string by limited HTML-entity & URL decoding, whitespace collapse, and trim.

| Param | Type | Description |
|---|---|---|
| `$s` | `string` | Raw input |

**Returns:** `string` — Normalized input

</details>

## `ThreatResult`

*final class* — `rafalmasiarek\Threat\Core\ThreatResult` · [source](https://github.com/rafalmasiarek/php-threat-detector/blob/main/src/Core/ThreatResult.php#L12)

Class ThreatResult Immutable result of a scan operation.

| Property | Type | Visibility | Description |
|---|---|---|---|
| `$suspect` | `bool` | public | Whether the input meets or exceeds the active threshold |
| `$score` | `float` | public | Weighted float score across categories |
| `$hits` | `array<string, array<int, string>>` | public | Map of category => list of hit codes |
| `$norm` | `string` | public | Normalized input string used for scanning |

| Method | Visibility | Returns | Summary |
|---|---|---|---|
| [`__construct()`](#threatresult-__construct) | public | — | — |
| [`toArray()`](#threatresult-toarray) | public | `array{suspect: bool, score: float, hits: array<string, array<int, string>>, norm: string}` | Export the result to a well-typed array (handy for logs). |

<details>
<summary><code>__construct()</code></summary>

#### `ThreatResult __construct()`

[source](https://github.com/rafalmasiarek/php-threat-detector/blob/main/src/Core/ThreatResult.php#L32)

```php
public function __construct(bool $suspect, float $score, array $hits, string $norm)
```

| Param | Type | Description |
|---|---|---|
| `$suspect` | `bool` | — |
| `$score` | `float` | — |
| `$hits` | `array<string, array<int, string>>` | — |
| `$norm` | `string` | — |

</details>

<details>
<summary><code>toArray()</code></summary>

#### `ThreatResult toArray()`

[source](https://github.com/rafalmasiarek/php-threat-detector/blob/main/src/Core/ThreatResult.php#L45)

```php
public function toArray(): array
```

Export the result to a well-typed array (handy for logs).

**Returns:** `array{suspect: bool, score: float, hits: array<string, array<int, string>>, norm: string}`

</details>

## `Thresholds`

*final class* — `rafalmasiarek\Threat\Core\Thresholds` · [source](https://github.com/rafalmasiarek/php-threat-detector/blob/main/src/Core/Thresholds.php#L12)

Class Thresholds Predefined float thresholds for suspicion decisions.

| Method | Visibility | Returns | Summary |
|---|---|---|---|
| [`resolve()`](#thresholds-resolve) | public static | `float` | Resolve a string keyword into a float threshold. |

<details>
<summary><code>resolve()</code></summary>

#### `Thresholds resolve()`

[source](https://github.com/rafalmasiarek/php-threat-detector/blob/main/src/Core/Thresholds.php#L24)

```php
public static function resolve(string $name): float
```

Resolve a string keyword into a float threshold.

| Param | Type | Description |
|---|---|---|
| `$name` | `string` | 'LOW'\|'MEDIUM'\|'HIGH' |

**Returns:** `float` — The resolved threshold

</details>

## `ThreatDetectMiddleware`

*final class* — `rafalmasiarek\Threat\Middleware\ThreatDetectMiddleware` · [source](https://github.com/rafalmasiarek/php-threat-detector/blob/main/src/Middleware/ThreatDetectMiddleware.php#L31)

Class ThreatDetectMiddleware PSR-15 middleware that scans selected parts of the request and attaches a compact result as request attribute. Options: - threshold: 'LOW'|'MEDIUM'|'HIGH'|float (default: 'MEDIUM') - weights: array<string,float> per-category overrides - scan_query (bool) - scan_body (bool) - scan_headers (bool|array) true or list of header names - scan_cookies (bool) - attribute (string) request attribute name (default: 'threat.result') - set_header (bool) set 'X-Threat-Suspect: 1' when suspect (default: true)

implements `MiddlewareInterface`

| Property | Type | Visibility | Description |
|---|---|---|---|
| `$config` | `array<string, mixed>` | private | — |

| Method | Visibility | Returns | Summary |
|---|---|---|---|
| [`__construct()`](#threatdetectmiddleware-__construct) | public | — | — |
| [`process()`](#threatdetectmiddleware-process) | public | `ResponseInterface` | {@inheritDoc} |
| [`scanArray()`](#threatdetectmiddleware-scanarray) | private | `void` | Scan nested arrays and accumulate score/hits. |
| [`mergeHits()`](#threatdetectmiddleware-mergehits) | private | `void` | Merge hit maps (category => codes[]) in-place. |

<details>
<summary><code>__construct()</code></summary>

#### `ThreatDetectMiddleware __construct()`

[source](https://github.com/rafalmasiarek/php-threat-detector/blob/main/src/Middleware/ThreatDetectMiddleware.php#L39)

```php
public function __construct(array $config)
```

| Param | Type | Description |
|---|---|---|
| `$config` | `array<string, mixed>` | Middleware configuration |

</details>

<details>
<summary><code>process()</code></summary>

#### `ThreatDetectMiddleware process()`

[source](https://github.com/rafalmasiarek/php-threat-detector/blob/main/src/Middleware/ThreatDetectMiddleware.php#L56)

```php
public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
```

{@inheritDoc}

| Param | Type | Description |
|---|---|---|
| `$request` | `ServerRequestInterface` | — |
| `$handler` | `RequestHandlerInterface` | — |

**Returns:** `ResponseInterface`

</details>

<details>
<summary><code>scanArray()</code></summary>

#### `ThreatDetectMiddleware scanArray()`

[source](https://github.com/rafalmasiarek/php-threat-detector/blob/main/src/Middleware/ThreatDetectMiddleware.php#L128)

```php
private function scanArray(array $arr, ThreatDetector $detector, float $accScore, array $accHits): void
```

Scan nested arrays and accumulate score/hits.

| Param | Type | Description |
|---|---|---|
| `$arr` | `array<string, mixed>` | — |
| `$detector` | [`ThreatDetector`](#threatdetector) | — |
| `$accScore` | `float` | (by-ref) |
| `$accHits` | `array<string, array<int, string>>` | (by-ref) |

</details>

<details>
<summary><code>mergeHits()</code></summary>

#### `ThreatDetectMiddleware mergeHits()`

[source](https://github.com/rafalmasiarek/php-threat-detector/blob/main/src/Middleware/ThreatDetectMiddleware.php#L146)

```php
private function mergeHits(array $into, array $from): void
```

Merge hit maps (category => codes[]) in-place.

| Param | Type | Description |
|---|---|---|
| `$into` | `array<string, array<int, string>>` | — |
| `$from` | `array<string, array<int, string>>` | — |

</details>

## `CmdInjectionScanner`

*final class* — `rafalmasiarek\Threat\Scanner\CmdInjectionScanner` · [source](https://github.com/rafalmasiarek/php-threat-detector/blob/main/src/Scanner/CmdInjectionScanner.php#L14)

Class CmdInjectionScanner Detects shell/command injection indicators.

implements [`ScannerInterface`](#scannerinterface)

| Method | Visibility | Returns | Summary |
|---|---|---|---|
| [`category()`](#cmdinjectionscanner-category) | public | `string` | — |
| [`scan()`](#cmdinjectionscanner-scan) | public | `array` | — |

<details>
<summary><code>category()</code></summary>

#### `CmdInjectionScanner category()`

[source](https://github.com/rafalmasiarek/php-threat-detector/blob/main/src/Scanner/CmdInjectionScanner.php#L16)

```php
public function category(): string
```

**Returns:** `string`

</details>

<details>
<summary><code>scan()</code></summary>

#### `CmdInjectionScanner scan()`

[source](https://github.com/rafalmasiarek/php-threat-detector/blob/main/src/Scanner/CmdInjectionScanner.php#L21)

```php
public function scan(string $normalized): array
```

| Param | Type | Description |
|---|---|---|
| `$normalized` | `string` | — |

**Returns:** `array`

</details>

## `CrlfScanner`

*final class* — `rafalmasiarek\Threat\Scanner\CrlfScanner` · [source](https://github.com/rafalmasiarek/php-threat-detector/blob/main/src/Scanner/CrlfScanner.php#L14)

Class CrlfScanner Detects CRLF/header injection attempts.

implements [`ScannerInterface`](#scannerinterface)

| Method | Visibility | Returns | Summary |
|---|---|---|---|
| [`category()`](#crlfscanner-category) | public | `string` | — |
| [`scan()`](#crlfscanner-scan) | public | `array` | — |

<details>
<summary><code>category()</code></summary>

#### `CrlfScanner category()`

[source](https://github.com/rafalmasiarek/php-threat-detector/blob/main/src/Scanner/CrlfScanner.php#L16)

```php
public function category(): string
```

**Returns:** `string`

</details>

<details>
<summary><code>scan()</code></summary>

#### `CrlfScanner scan()`

[source](https://github.com/rafalmasiarek/php-threat-detector/blob/main/src/Scanner/CrlfScanner.php#L21)

```php
public function scan(string $normalized): array
```

| Param | Type | Description |
|---|---|---|
| `$normalized` | `string` | — |

**Returns:** `array`

</details>

## `LdapScanner`

*final class* — `rafalmasiarek\Threat\Scanner\LdapScanner` · [source](https://github.com/rafalmasiarek/php-threat-detector/blob/main/src/Scanner/LdapScanner.php#L14)

Class LdapScanner Detects LDAP filter injection artifacts.

implements [`ScannerInterface`](#scannerinterface)

| Method | Visibility | Returns | Summary |
|---|---|---|---|
| [`category()`](#ldapscanner-category) | public | `string` | — |
| [`scan()`](#ldapscanner-scan) | public | `array` | — |

<details>
<summary><code>category()</code></summary>

#### `LdapScanner category()`

[source](https://github.com/rafalmasiarek/php-threat-detector/blob/main/src/Scanner/LdapScanner.php#L16)

```php
public function category(): string
```

**Returns:** `string`

</details>

<details>
<summary><code>scan()</code></summary>

#### `LdapScanner scan()`

[source](https://github.com/rafalmasiarek/php-threat-detector/blob/main/src/Scanner/LdapScanner.php#L21)

```php
public function scan(string $normalized): array
```

| Param | Type | Description |
|---|---|---|
| `$normalized` | `string` | — |

**Returns:** `array`

</details>

## `NoSqlScanner`

*final class* — `rafalmasiarek\Threat\Scanner\NoSqlScanner` · [source](https://github.com/rafalmasiarek/php-threat-detector/blob/main/src/Scanner/NoSqlScanner.php#L14)

Class NoSqlScanner Detects Mongo-like operator usage in input.

implements [`ScannerInterface`](#scannerinterface)

| Method | Visibility | Returns | Summary |
|---|---|---|---|
| [`category()`](#nosqlscanner-category) | public | `string` | — |
| [`scan()`](#nosqlscanner-scan) | public | `array` | — |

<details>
<summary><code>category()</code></summary>

#### `NoSqlScanner category()`

[source](https://github.com/rafalmasiarek/php-threat-detector/blob/main/src/Scanner/NoSqlScanner.php#L16)

```php
public function category(): string
```

**Returns:** `string`

</details>

<details>
<summary><code>scan()</code></summary>

#### `NoSqlScanner scan()`

[source](https://github.com/rafalmasiarek/php-threat-detector/blob/main/src/Scanner/NoSqlScanner.php#L21)

```php
public function scan(string $normalized): array
```

| Param | Type | Description |
|---|---|---|
| `$normalized` | `string` | — |

**Returns:** `array`

</details>

## `PathTraversalScanner`

*final class* — `rafalmasiarek\Threat\Scanner\PathTraversalScanner` · [source](https://github.com/rafalmasiarek/php-threat-detector/blob/main/src/Scanner/PathTraversalScanner.php#L14)

Class PathTraversalScanner Detects path traversal and file wrapper indicators.

implements [`ScannerInterface`](#scannerinterface)

| Method | Visibility | Returns | Summary |
|---|---|---|---|
| [`category()`](#pathtraversalscanner-category) | public | `string` | — |
| [`scan()`](#pathtraversalscanner-scan) | public | `array` | — |

<details>
<summary><code>category()</code></summary>

#### `PathTraversalScanner category()`

[source](https://github.com/rafalmasiarek/php-threat-detector/blob/main/src/Scanner/PathTraversalScanner.php#L16)

```php
public function category(): string
```

**Returns:** `string`

</details>

<details>
<summary><code>scan()</code></summary>

#### `PathTraversalScanner scan()`

[source](https://github.com/rafalmasiarek/php-threat-detector/blob/main/src/Scanner/PathTraversalScanner.php#L21)

```php
public function scan(string $normalized): array
```

| Param | Type | Description |
|---|---|---|
| `$normalized` | `string` | — |

**Returns:** `array`

</details>

## `SerializationScanner`

*final class* — `rafalmasiarek\Threat\Scanner\SerializationScanner` · [source](https://github.com/rafalmasiarek/php-threat-detector/blob/main/src/Scanner/SerializationScanner.php#L14)

Class SerializationScanner Detects PHP serialization patterns.

implements [`ScannerInterface`](#scannerinterface)

| Method | Visibility | Returns | Summary |
|---|---|---|---|
| [`category()`](#serializationscanner-category) | public | `string` | — |
| [`scan()`](#serializationscanner-scan) | public | `array` | — |

<details>
<summary><code>category()</code></summary>

#### `SerializationScanner category()`

[source](https://github.com/rafalmasiarek/php-threat-detector/blob/main/src/Scanner/SerializationScanner.php#L16)

```php
public function category(): string
```

**Returns:** `string`

</details>

<details>
<summary><code>scan()</code></summary>

#### `SerializationScanner scan()`

[source](https://github.com/rafalmasiarek/php-threat-detector/blob/main/src/Scanner/SerializationScanner.php#L21)

```php
public function scan(string $normalized): array
```

| Param | Type | Description |
|---|---|---|
| `$normalized` | `string` | — |

**Returns:** `array`

</details>

## `SqliScanner`

*final class* — `rafalmasiarek\Threat\Scanner\SqliScanner` · [source](https://github.com/rafalmasiarek/php-threat-detector/blob/main/src/Scanner/SqliScanner.php#L14)

Class SqliScanner Detects common SQL injection patterns.

implements [`ScannerInterface`](#scannerinterface)

| Method | Visibility | Returns | Summary |
|---|---|---|---|
| [`category()`](#sqliscanner-category) | public | `string` | — |
| [`scan()`](#sqliscanner-scan) | public | `array` | — |

<details>
<summary><code>category()</code></summary>

#### `SqliScanner category()`

[source](https://github.com/rafalmasiarek/php-threat-detector/blob/main/src/Scanner/SqliScanner.php#L16)

```php
public function category(): string
```

**Returns:** `string`

</details>

<details>
<summary><code>scan()</code></summary>

#### `SqliScanner scan()`

[source](https://github.com/rafalmasiarek/php-threat-detector/blob/main/src/Scanner/SqliScanner.php#L21)

```php
public function scan(string $normalized): array
```

| Param | Type | Description |
|---|---|---|
| `$normalized` | `string` | — |

**Returns:** `array`

</details>

## `SsrfScanner`

*final class* — `rafalmasiarek\Threat\Scanner\SsrfScanner` · [source](https://github.com/rafalmasiarek/php-threat-detector/blob/main/src/Scanner/SsrfScanner.php#L14)

Class SsrfScanner Detects SSRF indicators (localhost, RFC1918 networks).

implements [`ScannerInterface`](#scannerinterface)

| Method | Visibility | Returns | Summary |
|---|---|---|---|
| [`category()`](#ssrfscanner-category) | public | `string` | — |
| [`scan()`](#ssrfscanner-scan) | public | `array` | — |

<details>
<summary><code>category()</code></summary>

#### `SsrfScanner category()`

[source](https://github.com/rafalmasiarek/php-threat-detector/blob/main/src/Scanner/SsrfScanner.php#L16)

```php
public function category(): string
```

**Returns:** `string`

</details>

<details>
<summary><code>scan()</code></summary>

#### `SsrfScanner scan()`

[source](https://github.com/rafalmasiarek/php-threat-detector/blob/main/src/Scanner/SsrfScanner.php#L21)

```php
public function scan(string $normalized): array
```

| Param | Type | Description |
|---|---|---|
| `$normalized` | `string` | — |

**Returns:** `array`

</details>

## `XssScanner`

*final class* — `rafalmasiarek\Threat\Scanner\XssScanner` · [source](https://github.com/rafalmasiarek/php-threat-detector/blob/main/src/Scanner/XssScanner.php#L14)

Class XssScanner Detects common indicators of Cross-Site Scripting (XSS).

implements [`ScannerInterface`](#scannerinterface)

| Method | Visibility | Returns | Summary |
|---|---|---|---|
| [`category()`](#xssscanner-category) | public | `string` | — |
| [`scan()`](#xssscanner-scan) | public | `array` | — |

<details>
<summary><code>category()</code></summary>

#### `XssScanner category()`

[source](https://github.com/rafalmasiarek/php-threat-detector/blob/main/src/Scanner/XssScanner.php#L16)

```php
public function category(): string
```

**Returns:** `string`

</details>

<details>
<summary><code>scan()</code></summary>

#### `XssScanner scan()`

[source](https://github.com/rafalmasiarek/php-threat-detector/blob/main/src/Scanner/XssScanner.php#L21)

```php
public function scan(string $normalized): array
```

| Param | Type | Description |
|---|---|---|
| `$normalized` | `string` | — |

**Returns:** `array`

</details>

## `XxeScanner`

*final class* — `rafalmasiarek\Threat\Scanner\XxeScanner` · [source](https://github.com/rafalmasiarek/php-threat-detector/blob/main/src/Scanner/XxeScanner.php#L14)

Class XxeScanner Detects XML External Entity (XXE) indicators.

implements [`ScannerInterface`](#scannerinterface)

| Method | Visibility | Returns | Summary |
|---|---|---|---|
| [`category()`](#xxescanner-category) | public | `string` | — |
| [`scan()`](#xxescanner-scan) | public | `array` | — |

<details>
<summary><code>category()</code></summary>

#### `XxeScanner category()`

[source](https://github.com/rafalmasiarek/php-threat-detector/blob/main/src/Scanner/XxeScanner.php#L16)

```php
public function category(): string
```

**Returns:** `string`

</details>

<details>
<summary><code>scan()</code></summary>

#### `XxeScanner scan()`

[source](https://github.com/rafalmasiarek/php-threat-detector/blob/main/src/Scanner/XxeScanner.php#L21)

```php
public function scan(string $normalized): array
```

| Param | Type | Description |
|---|---|---|
| `$normalized` | `string` | — |

**Returns:** `array`

</details>




<!-- references -->

[repo_link]: https://github.com/rafalmasiarek/php-threat-detector
