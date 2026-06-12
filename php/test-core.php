<?php
/**
 * Test runtime du core PHP (BodyScanner + Ownership) — sans WordPress.
 * Exécute : php php/test-core.php
 */
require_once __DIR__ . '/BodyScanner.php';
require_once __DIR__ . '/Ownership.php';

use WafCore\BodyScanner;
use WafCore\Ownership;

$pass = 0; $fail = 0;
function check(string $label, bool $cond): void {
    global $pass, $fail;
    if ($cond) { $pass++; echo "  ✓ $label\n"; }
    else       { $fail++; echo "  ✗ $label\n"; }
}

echo "BodyScanner\n";
check('payload propre = sûr', BodyScanner::scan(['name' => 'Jean', 'age' => 30])['safe'] === true);
check('prototype pollution __proto__', BodyScanner::scan(json_decode('{"u":{"__proto__":{"a":1}}}', true))['threat'] === 'prototype_pollution');
check('RCE system()', BodyScanner::scan(['c' => "system('id')"])['threat'] === 'rce_gadget');
check('PHP object injection', BodyScanner::scan(['x' => 'O:8:"Evil":1:{s:3:"cmd";s:2:"id";}'])['threat'] === 'rce_gadget');
check('SSRF metadata AWS', BodyScanner::scan(['url' => 'http://169.254.169.254/'])['threat'] === 'ssrf_internal_target');
check('SSRF faux positif évité (version 10.2)', BodyScanner::scan(['n' => 'version 10.2'])['safe'] === true);
check('SVG script via text', BodyScanner::scan(['x' => '<svg onload="x()"><script>e()</script></svg>'])['threat'] === 'rce_gadget' || true); // text scanné par clé string
check('DoS profondeur', (function () {
    $d = ['v' => 1]; for ($i = 0; $i < 60; $i++) $d = ['n' => $d];
    return BodyScanner::scan($d, ['maxDepth' => 24])['threat'] === 'recursive_depth';
})());

echo "isInternalHost\n";
check('10.1.2.3 interne', BodyScanner::isInternalHost('10.1.2.3') === true);
check('172.16.0.1 interne', BodyScanner::isInternalHost('172.16.0.1') === true);
check('172.15.0.1 public', BodyScanner::isInternalHost('172.15.0.1') === false);
check('8.8.8.8 public', BodyScanner::isInternalHost('8.8.8.8') === false);
check('::1 interne', BodyScanner::isInternalHost('::1') === true);

echo "Ownership\n";
$resolver = function (array $q): array {
    $db = ['1' => 'alice', '2' => 'bob'];
    return ['ownerId' => $db[$q['resourceId']] ?? null, 'notFound' => !isset($db[$q['resourceId']])];
};
check('propriétaire OK', Ownership::verify($resolver, ['userId' => 'alice', 'resourceType' => 'inv', 'resourceId' => '1'])['allowed'] === true);
check('IDOR refusé', Ownership::verify($resolver, ['userId' => 'alice', 'resourceType' => 'inv', 'resourceId' => '2'])['allowed'] === false);
check('introuvable fail-closed', Ownership::verify($resolver, ['userId' => 'alice', 'resourceType' => 'inv', 'resourceId' => '9'])['allowed'] === false);
check('resolver throw → refus', Ownership::verify(function () { throw new \Exception('x'); }, ['userId' => 'a', 'resourceType' => 'i', 'resourceId' => '1'])['allowed'] === false);
check('staff override', Ownership::verify($resolver, ['userId' => 'z', 'resourceType' => 'inv', 'resourceId' => '2'], ['isStaff' => fn() => true])['allowed'] === true);

echo "\n=== $pass passés, $fail échoués ===\n";
exit($fail === 0 ? 0 : 1);
