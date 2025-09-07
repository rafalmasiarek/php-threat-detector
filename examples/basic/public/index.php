<?php

declare(strict_types=1);

// Dev autoloader (no Composer/vendor needed)
require __DIR__ . '/../autoload.php';

use rafalmasiarek\Threat\Core\ThreatDetector;
use rafalmasiarek\Threat\Core\ScoringPolicy;
use rafalmasiarek\Threat\Core\Thresholds;

// Build policy from query (?threshold=LOW|MEDIUM|HIGH|float)
$threshold = $_GET['threshold'] ?? 'MEDIUM';
$policy = ScoringPolicy::withDefaults()->withThreshold($threshold);

// Detector with default scanners
$detector = ThreatDetector::default($policy);

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

// Which checkboxes were ticked (only for restoring state)
$selected = array_values(array_intersect(
  array_keys($payloads),
  (array)($_POST['presets'] ?? [])
));

// Input policy: DO NOT overwrite user content with presets.
// On first load (GET), prefill with a benign example; on POST keep textarea as-is.
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  $input = (string)($_POST['input'] ?? '');
} else {
  $input = 'Hello world & have a nice day!';
}

// Run scan if submitted
$result = null;
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  $result = $detector->scanString($input);
}
?>
<!doctype html>
<html lang="en">

<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Threat Detector Demo</title>
  <link rel="stylesheet" href="/style.css" />
</head>

<body>
  <div class="container">
    <div class="card">
      <h1>Threat Detector Demo</h1>
      <small>Threshold:
        <a href="?threshold=LOW">LOW</a> ·
        <a href="?threshold=MEDIUM">MEDIUM</a> ·
        <a href="?threshold=HIGH">HIGH</a>
      </small>
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
          <label for="threshold">Active threshold</label>
          <input id="threshold" value="<?= htmlspecialchars((string)$threshold) ?>" readonly />
        </div>
      </div>

      <label for="input">Input</label>
      <textarea id="input" name="input" rows="8" class="code"><?=
                                                              htmlspecialchars((string)$input, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
                                                              ?></textarea>

      <div style="margin-top:10px; display:flex; gap:10px; justify-content:flex-end">
        <button type="button" id="btnClear" title="Clear textarea and uncheck all">Clear</button>
        <button type="submit">Scan</button>
      </div>
    </form>

    <?php if ($result): ?>
      <div class="card">
        <h2>Result</h2>
        <?php if ($result->suspect): ?>
          <span class="badge suspect">SUSPECT</span>
        <?php else: ?>
          <span class="badge pass">PASS</span>
        <?php endif; ?>
        <p><strong>Score:</strong> <?= number_format($result->score, 2, '.', '') ?></p>

        <details>
          <summary>Normalized input</summary>
          <pre class="code"><?= htmlspecialchars($result->norm, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?></pre>
        </details>

        <h3>Hits</h3>
        <?php if (empty($result->hits)): ?>
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
              <?php foreach ($result->hits as $cat => $codes): ?>
                <tr>
                  <td><?= htmlspecialchars($cat) ?></td>
                  <td><?= htmlspecialchars(implode(', ', $codes)) ?></td>
                </tr>
              <?php endforeach; ?>
            </tbody>
          </table>
        <?php endif; ?>
      </div>
    <?php endif; ?>
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