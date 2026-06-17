<?php
/**
 * Tests d'exécution du moteur du plugin KeysO-WAF (sans WordPress).
 *
 * Vérifie le cœur de sécurité réellement embarqué dans le plugin :
 *   • BodyScanner  : détection prototype pollution / RCE / SSRF / DoS
 *   • Ownership    : autorisation au niveau objet (anti-IDOR/BOLA)
 *   • IdorRules    : safeIdent (anti-injection d'identifiant SQL)
 *   • Guard        : détection d'IP cliente (fix anti-spoofing)
 *
 * Usage : php wordpress-plugin/tests/test-plugin.php
 */

define('ABSPATH', __DIR__ . '/');           // simule l'environnement WP
$PLUGIN = dirname(__DIR__) . '/keyso-waf';

// ── Stubs minimaux des fonctions WordPress utilisées par les méthodes testées ──
if (!function_exists('keyso_waf_get_options')) {
    $GLOBALS['__opts'] = [];
    function keyso_waf_get_options(): array { return $GLOBALS['__opts']; }
}

// Stubs transients (in-memory) + object cache pour tester le rate-limit / lockout
if (!function_exists('wp_using_ext_object_cache')) {
    function wp_using_ext_object_cache(): bool { return false; }
}
if (!function_exists('get_transient')) {
    $GLOBALS['__tr'] = [];
    function get_transient(string $k) { return $GLOBALS['__tr'][$k] ?? false; }
    function set_transient(string $k, $v, $ttl = 0): bool { $GLOBALS['__tr'][$k] = $v; return true; }
    function delete_transient(string $k): bool { unset($GLOBALS['__tr'][$k]); return true; }
}

require_once $PLUGIN . '/includes/BodyScanner.php';
require_once $PLUGIN . '/includes/Ownership.php';
require_once $PLUGIN . '/includes/class-waf-idor-rules.php';
require_once $PLUGIN . '/includes/class-waf-guard.php';
require_once $PLUGIN . '/includes/class-waf-rate-limit.php';
require_once $PLUGIN . '/includes/class-waf-hardening.php';
require_once $PLUGIN . '/includes/class-waf-2fa.php';
require_once $PLUGIN . '/includes/class-waf-logger.php';

use WafCore\BodyScanner;
use WafCore\Ownership;
use KeysO_WAF\IdorRules;
use KeysO_WAF\Guard;

$pass = 0; $fail = 0;
function ok(bool $cond, string $label): void {
    global $pass, $fail;
    if ($cond) { $pass++; echo "  ✓ $label\n"; }
    else { $fail++; echo "  ✗ ÉCHEC : $label\n"; }
}

echo "\n=== BodyScanner — détection structurelle ===\n";
ok(BodyScanner::scan(['name' => 'Jean', 'age' => 30])['safe'] === true, 'payload légitime accepté');
ok(BodyScanner::scan(json_decode('{"__proto__":{"admin":true}}', true))['threat'] === 'prototype_pollution', 'prototype pollution détectée');
ok(BodyScanner::scan(['cb' => 'require("child_process").exec("rm -rf /")'])['threat'] === 'rce_gadget', 'gadget RCE (child_process) détecté');
ok(BodyScanner::scan(['x' => 'shell_exec($_GET[c])'])['threat'] === 'rce_gadget', 'gadget RCE (shell_exec) détecté');
ok(BodyScanner::scan(['url' => 'http://169.254.169.254/latest/meta-data/'])['threat'] === 'ssrf_internal_target', 'SSRF cloud-metadata détecté');
ok(BodyScanner::scan(['url' => 'file:///etc/passwd'])['threat'] === 'ssrf_internal_target', 'SSRF schéma file:// détecté');
ok(BodyScanner::scan(['s' => str_repeat('A', 60000)])['threat'] === 'oversized_string', 'chaîne géante (DoS) détectée');
$deep = '0'; for ($i = 0; $i < 30; $i++) { $deep = [$deep]; }
ok(BodyScanner::scan($deep)['threat'] === 'recursive_depth', 'profondeur excessive (DoS) détectée');

echo "\n=== Ownership — anti-IDOR / BOLA ===\n";
$resolver = fn(array $q) => ['ownerId' => '42', 'notFound' => false];
ok(Ownership::verify($resolver, ['userId' => '42', 'resourceType' => 'order', 'resourceId' => '7'])['allowed'] === true, 'propriétaire légitime autorisé');
ok(Ownership::verify($resolver, ['userId' => '99', 'resourceType' => 'order', 'resourceId' => '7'])['allowed'] === false, 'usurpateur (IDOR) refusé');
$missing = fn(array $q) => ['ownerId' => null, 'notFound' => true];
ok(Ownership::verify($missing, ['userId' => '42', 'resourceType' => 'o', 'resourceId' => '1'], ['missingPolicy' => 'deny'])['allowed'] === false, 'ressource introuvable → deny (fail-closed)');

echo "\n=== IdorRules::safeIdent — anti-injection SQL ===\n";
ok(IdorRules::safeIdent('post_author') === 'post_author', 'identifiant valide conservé');
ok(IdorRules::safeIdent('id; DROP TABLE users;--') === 'idDROPTABLEusers', 'injection SQL neutralisée');
ok(IdorRules::safeIdent('`owner`') === 'owner', 'backticks retirés');

echo "\n=== Guard::staticClientIp — fix anti-spoofing IP ===\n";
$_SERVER['REMOTE_ADDR'] = '203.0.113.10';
$_SERVER['HTTP_X_FORWARDED_FOR'] = '1.2.3.4';
// Défaut (trusted_ip_header vide) → DOIT ignorer X-Forwarded-For
$GLOBALS['__opts'] = ['trusted_ip_header' => ''];
ok(Guard::staticClientIp() === '203.0.113.10', "défaut : REMOTE_ADDR utilisé, XFF falsifié ignoré");
// Proxy explicitement configuré → lit l'en-tête
$GLOBALS['__opts'] = ['trusted_ip_header' => 'HTTP_X_FORWARDED_FOR'];
ok(Guard::staticClientIp() === '1.2.3.4', 'proxy configuré : en-tête de confiance lu');
// En-tête de confiance configuré mais absent → repli REMOTE_ADDR
unset($_SERVER['HTTP_X_FORWARDED_FOR']);
ok(Guard::staticClientIp() === '203.0.113.10', 'en-tête absent : repli sur REMOTE_ADDR');

echo "\n=== RateLimit — rate-limiting & lockout brute-force ===\n";
$GLOBALS['__tr'] = [];
$over = false;
for ($i = 0; $i < 6; $i++) { if (\KeysO_WAF\RateLimit::hit('req_1.2.3.4', 5, 60)) $over = true; }
ok($over === true, 'rate-limit : dépassement détecté au-delà du seuil');
$GLOBALS['__tr'] = [];
ok(\KeysO_WAF\RateLimit::isLoginLocked('1.2.3.4') === false, 'IP non verrouillée au départ');
for ($i = 0; $i < 5; $i++) { \KeysO_WAF\RateLimit::registerFailedLogin('1.2.3.4', 5, 15); }
ok(\KeysO_WAF\RateLimit::isLoginLocked('1.2.3.4') === true, 'lockout après 5 échecs de login (brute-force)');
\KeysO_WAF\RateLimit::clearFailedLogin('1.2.3.4');
ok(\KeysO_WAF\RateLimit::isLoginLocked('1.2.3.4') === false, 'déverrouillage après login réussi');

echo "\n=== Hardening — détection SQLi (paramètres) ===\n";
ok(\KeysO_WAF\Hardening::looksLikeSqli("1 UNION SELECT user_login,user_pass FROM wp_users") === true, 'UNION SELECT détecté');
ok(\KeysO_WAF\Hardening::looksLikeSqli("1' OR '1'='1") === true, "boolean ' OR '1'='1 détecté");
ok(\KeysO_WAF\Hardening::looksLikeSqli("1; DROP TABLE wp_users") === true, 'stacked DROP détecté');
ok(\KeysO_WAF\Hardening::looksLikeSqli("1 AND sleep(5)") === true, 'time-based sleep() détecté');
ok(\KeysO_WAF\Hardening::looksLikeSqli("admin' AND extractvalue(1,concat(0x7e,version()))") === true, 'error-based extractvalue détecté');
ok(\KeysO_WAF\Hardening::looksLikeSqli('comment organiser un voyage') === false, 'phrase légitime non flaggée');
ok(\KeysO_WAF\Hardening::looksLikeSqli('selection de produits') === false, 'mot "selection" non flaggé (faux positif évité)');
ok(\KeysO_WAF\Hardening::looksLikeSqli('Alexandre') === false, 'prénom non flaggé');

echo "\n=== 2FA — TOTP (RFC 6238) ===\n";
$b32 = \KeysO_WAF\TwoFactor::base32Encode("Hello!");
ok(\KeysO_WAF\TwoFactor::base32Decode($b32) === "Hello!", 'base32 aller-retour correct');
$secret = \KeysO_WAF\TwoFactor::base32Encode(random_bytes(20));
$now = time();
$valid = \KeysO_WAF\TwoFactor::code($secret, $now);
ok(\KeysO_WAF\TwoFactor::verify($secret, $valid) === true, 'code TOTP courant accepté');
ok(\KeysO_WAF\TwoFactor::verify($secret, '000000') === false || $valid === '000000', 'code erroné rejeté');
ok(\KeysO_WAF\TwoFactor::verify($secret, \KeysO_WAF\TwoFactor::code($secret, $now - 120)) === false, 'code expiré (-120s) rejeté');
// Vecteur RFC 6238 connu (secret ASCII "12345678901234567890" en base32, T=59)
$rfcSecret = \KeysO_WAF\TwoFactor::base32Encode('12345678901234567890');
ok(\KeysO_WAF\TwoFactor::code($rfcSecret, 59) === '287082', 'vecteur de test RFC 6238 (T=59 → 287082)');

echo "\n=== Mots de passe forts (anti cassage par dictionnaire) ===\n";
ok(\KeysO_WAF\Hardening::isWeakPassword('password123') === true, 'mot de passe commun rejeté');
ok(\KeysO_WAF\Hardening::isWeakPassword('Soleil2024') === true, 'trop court (<12) rejeté');
ok(\KeysO_WAF\Hardening::isWeakPassword('Tr0ub4dour&3xplore!') === false, 'mot de passe fort accepté');
ok(\KeysO_WAF\Hardening::isWeakPassword('MotDePasseAdmin', 'admin') === true, 'contient l\'identifiant → rejeté');

echo "\n=== Défense active — auto-ban comportemental ===\n";
$GLOBALS['__tr'] = [];
$GLOBALS['__opts'] = ['auto_ban_enabled' => 1, 'auto_ban_threshold' => 5, 'auto_ban_window' => 600, 'auto_ban_duration' => 3600];
ok(\KeysO_WAF\Logger::isAutoBanned('9.9.9.9') === false, 'IP propre non bannie au départ');
for ($i = 0; $i < 5; $i++) { \KeysO_WAF\Logger::recordViolation('9.9.9.9'); }
ok(\KeysO_WAF\Logger::isAutoBanned('9.9.9.9') === true, 'auto-ban après 5 violations (défense active)');
ok(\KeysO_WAF\Logger::isAutoBanned('1.1.1.1') === false, 'autre IP non affectée');
$GLOBALS['__opts'] = ['auto_ban_enabled' => 0];
$GLOBALS['__tr'] = [];
for ($i = 0; $i < 8; $i++) { \KeysO_WAF\Logger::recordViolation('8.8.8.8'); }
ok(\KeysO_WAF\Logger::isAutoBanned('8.8.8.8') === false, 'auto-ban désactivé → aucun ban');

echo "\n────────────────────────────────────────\n";
echo ($fail === 0 ? "✅ TOUS LES TESTS PASSENT" : "❌ $fail ÉCHEC(S)") . "  ($pass réussis)\n";
exit($fail === 0 ? 0 : 1);
