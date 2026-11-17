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

