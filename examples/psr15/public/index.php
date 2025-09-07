<?php

declare(strict_types=1);

// PSR shims (in examples/psr15/)
require __DIR__ . '/../psr15/psr-shim.php';
require __DIR__ . '/../psr15/psr15-shim.php';
require __DIR__ . '/../psr15/pipeline.php';

// Dev autoloader (in examples/)
require __DIR__ . '/../autoload.php';

use Psr\Http\Message\ServerRequest;
use Demo\Runner\Pipeline;
use Demo\Runner\FinalHandler;
use rafalmasiarek\Threat\Middleware\ThreatDetectMiddleware;

// Build the request from globals
$request = new ServerRequest();

// Configure middleware
$mw = new ThreatDetectMiddleware([
  'threshold'    => $_GET['threshold'] ?? 'MEDIUM',
  'weights'      => [],
  'scan_query'   => true,
  'scan_body'    => true,
  'scan_headers' => ['User-Agent'],
  'scan_cookies' => false,
  'attribute'    => 'threat.result',
  'set_header'   => true,
]);

// Predefined payloads (for quick testing)
$payloads = [
  'Benign: greeting' => 'Hello world & have a nice day!',
  'XSS: <script>' => '<script>alert(1)</script>',
  'XSS: img onerror' => '<img src=x onerror=alert(1)>',
  'XSS: javascript URI' => 'javascript:alert(1)',
  'SQLi: UNION SELECT' => 'UNION SELECT password FROM users',
  'SQLi: boolean OR' => "' OR 1=1 --",
  'CMD: rm; curl' => 'rm -rf /; curl http://127.0.0.1/shell.sh',
  'Path traversal: ../etc/passwd' => '../../etc/passwd',
  'CRLF: header inject' => "Hello%0aX-Injected: evil",
  'SSRF: localhost URL' => 'http://127.0.0.1/admin',
  'XXE: SYSTEM external' => '<!DOCTYPE x [<!ENTITY ext SYSTEM "file:///etc/passwd">]><x>&ext;</x>',
  'NoSQL: $where' => '{"$where":"this.password.hash()"}',
  'LDAP: wildcard OR' => '(|(cn=*)(uid=*))',
  'PHP serialization' => 'O:8:"stdClass":1:{s:3:"foo";s:3:"bar";}',
];

// Which checkboxes were ticked (for restoring state only)
$selected = array_values(array_intersect(
  array_keys($payloads),
  (array)($_POST['presets'] ?? [])
));

// Input policy: DO NOT overwrite user content with presets.
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  $input = (string)($_POST['input'] ?? '');
} else {
  $input = 'Hello world & have a nice day!';
}

// Final handler renders the result attribute
$handler = new FinalHandler(function ($request) use ($payloads, $selected, $input) {
  $result = $request->getAttribute('threat.result', ['suspect' => false, 'score' => 0, 'hits' => []]);
  $threshold = htmlspecialchars((string)($_GET['threshold'] ?? 'MEDIUM'));
  ob_start(); ?>
  <!doctype html>
  <html lang="en">

  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>PSR-15 Demo</title>
    <link rel="stylesheet" href="/style.css" />
  </head>

  <body>
    <div class="container">
      <div class="card">
        <h1>PSR-15 Middleware Demo</h1>
        <small>Threshold: <a href="?threshold=LOW">LOW</a> · <a href="?threshold=MEDIUM">MEDIUM</a> · <a href="?threshold=HIGH">HIGH</a></small>
      </div>

      <form class="card" method="post">
        <div class="grid">
          <div>
            <label>Preset payloads</label>
            <div style="display:grid; gap:6px; grid-template-columns:1fr 1fr;">
              <div class="preset-list">
                <?php foreach ($payloads as $label => $value): ?>
                  <label>
                    <input
                      type="checkbox"
                      name="presets[]"
                      value="<?= htmlspecialchars($label) ?>"
                      <?= in_array($label, $selected, true) ? 'checked' : '' ?> />
                    <span><?= htmlspecialchars($label) ?></span>
                  </label>
                <?php endforeach; ?>
              </div>
            </div>
          </div>
          <div>
            <label>Active threshold</label>
            <input value="<?= $threshold ?>" readonly />
          </div>
        </div>

        <label for="input">Input</label>
        <textarea id="input" name="input" rows="8" class="code"><?=
                                                                htmlspecialchars((string)$input, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
                                                                ?></textarea>

        <div style="margin-top:10px; display:flex; gap:10px; justify-content:flex-end">
          <button type="button" id="btnClear" title="Clear textarea and uncheck all">Clear</button>
          <button type="submit">Send</button>
        </div>
      </form>

      <div class="card">
        <h2>Result from middleware</h2>
        <?php if (!empty($result['suspect'])): ?>
          <span class="badge suspect">SUSPECT</span>
        <?php else: ?>
          <span class="badge pass">PASS</span>
        <?php endif; ?>

        <p><strong>Score:</strong> <?= number_format((float)$result['score'], 2, '.', '') ?></p>
        <h3>Hits</h3>
        <?php if (empty($result['hits'])): ?>
          <p><em>No hits.</em></p>
        <?php else: ?>
          <table>
            <thead>
              <tr>
                <th>Category</th>
                <th>Codes</th>
              </tr>
            </thead>
            <tbody>
              <?php foreach ($result['hits'] as $cat => $codes): ?>
                <tr>
                  <td><?= htmlspecialchars($cat) ?></td>
                  <td><?= htmlspecialchars(implode(', ', $codes)) ?></td>
                </tr>
              <?php endforeach; ?>
            </tbody>
          </table>
        <?php endif; ?>
        <small>Header <code>X-Threat-Suspect</code> is also set when suspect.</small>
      </div>
    </div>

    <script>
      const PRESETS = <?php
                      echo json_encode(
                        $payloads,
                        JSON_UNESCAPED_UNICODE
                          | JSON_UNESCAPED_SLASHES
                          | JSON_HEX_TAG
                          | JSON_HEX_AMP
                          | JSON_HEX_APOS
                          | JSON_HEX_QUOT
                      );
                      ?>;

      /** Append/remove exact preset payloads without overwriting user's custom text. */
      function addPayload(text) {
        const ta = document.getElementById('input');
        const lines = ta.value.split(/\r?\n/);
        if (!lines.includes(text)) lines.push(text);
        ta.value = lines.filter(l => l.length > 0).join("\n");
      }

      function removePayload(text) {
        const ta = document.getElementById('input');
        const lines = ta.value.split(/\r?\n/).filter(l => l !== text);
        ta.value = lines.join("\n");
      }

      function rebuildFromCheckboxChange(ev) {
        const cb = ev.target;
        const key = cb.value;
        const val = PRESETS[key] || "";
        if (cb.checked) addPayload(val);
        else removePayload(val);
      }

      function clearAll() {
        document.getElementById('input').value = "";
        document.querySelectorAll('input[name="presets[]"]').forEach(cb => cb.checked = false);
      }

      window.addEventListener('DOMContentLoaded', () => {
        document.querySelectorAll('input[name="presets[]"]').forEach(cb => {
          cb.addEventListener('change', rebuildFromCheckboxChange);
        });
        document.getElementById('btnClear').addEventListener('click', clearAll);
      });
    </script>
  </body>

  </html>
<?php
  return ob_get_clean();
});

$pipeline = new Pipeline($handler);
$pipeline->pipe($mw);

// Execute
$response = $pipeline->handle($request);

// Emit response
http_response_code($response->getStatusCode());
foreach ($response->getHeaders() as $name => $vals) {
  foreach ($vals as $v) header("$name: $v", false);
}
echo $response->getBody();
