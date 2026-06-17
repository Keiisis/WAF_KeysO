<?php
/**
 * Plugin Name:       KeysO-WAF — Pare-feu applicatif surpuissant
 * Plugin URI:        https://github.com/Keiisis/WAF_KeysO
 * Description:        WAF nouvelle génération : analyse structurelle des payloads (Prototype Pollution, RCE, SSRF, DoS), autorisation au niveau objet (anti-IDOR/BOLA), protection brute-force, rate-limiting, honeypot et journal de sécurité. Léger, sans dépendance externe.
 * Version:           1.7.1
 * Requires at least: 5.8
 * Requires PHP:      8.0
 * Author:            KeysO
 * Author URI:        https://github.com/Keiisis
 * License:           Proprietary (commercial license — see LICENSE)
 * Text Domain:       keyso-waf
 *
 * @package KeysO_WAF
 */

if (!defined('ABSPATH')) {
    exit; // Pas d'accès direct
}

define('KEYSO_WAF_VERSION', '1.7.1');
define('KEYSO_WAF_FILE', __FILE__);
define('KEYSO_WAF_DIR', plugin_dir_path(__FILE__));
define('KEYSO_WAF_URL', plugin_dir_url(__FILE__));
define('KEYSO_WAF_TABLE', 'keyso_waf_logs');

// Serveur de licences (anti-piratage). Pointez vers VOTRE endpoint de
// vérification, ou définissez-le dans wp-config.php. Vide = mode communautaire
// (protection cœur active, fonctions premium désactivées).
if (!defined('KEYSO_WAF_LICENSE_API')) {
    define('KEYSO_WAF_LICENSE_API', ''); // ex: 'https://www.retourgagnantbenin.bj/api/license/verify'
}

// ── Core portable (port PHP) ──────────────────────────────────
require_once KEYSO_WAF_DIR . 'includes/BodyScanner.php';
require_once KEYSO_WAF_DIR . 'includes/Ownership.php';

// ── Modules du plugin ─────────────────────────────────────────
require_once KEYSO_WAF_DIR . 'includes/class-waf-license.php';
require_once KEYSO_WAF_DIR . 'includes/class-waf-logger.php';
require_once KEYSO_WAF_DIR . 'includes/class-waf-alerts.php';
require_once KEYSO_WAF_DIR . 'includes/class-waf-rate-limit.php';
require_once KEYSO_WAF_DIR . 'includes/class-waf-idor-rules.php';
require_once KEYSO_WAF_DIR . 'includes/class-waf-hardening.php';
require_once KEYSO_WAF_DIR . 'includes/class-waf-2fa.php';
require_once KEYSO_WAF_DIR . 'includes/class-waf-guard.php';
require_once KEYSO_WAF_DIR . 'includes/class-waf-admin.php';

// ── i18n : chargement des traductions (.pot/.mo dans /languages) ──
add_action('init', function () {
    load_plugin_textdomain('keyso-waf', false, dirname(plugin_basename(__FILE__)) . '/languages');
});

/**
 * Options par défaut (créées à l'activation).
 *
 * @return array<string,mixed>
 */
function keyso_waf_default_options(): array
{
    return [
        'enabled'             => 1,
        'scan_rest_bodies'    => 1,  // #2 analyse structurelle des requêtes REST
        'protect_login'       => 1,  // brute-force lockout
        'rate_limit'          => 1,  // limite de requêtes par IP
        'block_honeypot'      => 1,  // chemins pièges (xmlrpc abuse, etc.)
        'security_headers'    => 1,  // X-Frame-Options, nosniff, etc.
        'login_max_attempts'  => 5,  // tentatives avant lockout
        'login_lockout_min'   => 15, // durée de lockout (minutes)
        'rate_limit_max'      => 120, // requêtes / fenêtre
        'rate_limit_window'   => 60,  // fenêtre (secondes)
        'whitelist_ips'       => '',  // IPs exemptées (une par ligne)
        // IP réelle du client : par défaut REMOTE_ADDR (NON falsifiable).
        // À régler sur un en-tête proxy UNIQUEMENT si le site est derrière ce
        // proxy/CDN (sinon un attaquant falsifie son IP → bypass whitelist + rate-limit).
        'trusted_ip_header'   => '',
        'blocklist_ips'       => '',  // IPs bloquées d'office (une par ligne)
        'scan_front_post'     => 0,   // scanner les POST de formulaires front
        'block_message'       => '',  // message de blocage personnalisé (vide = défaut)

        // ── Durcissement WordPress ──
        'sqli_detection'      => 1,   // détection injection SQL (GET / query string)
        'block_user_enum'     => 1,   // anti-énumération (?author=, REST /users)
        'generic_login_errors' => 1,  // messages de login génériques
        'disable_xmlrpc'      => 0,   // désactiver XML-RPC (off : Jetpack/app peuvent l'utiliser)
        'db_integrity_alerts' => 1,   // alerte création/élévation administrateur
        'enforce_strong_passwords' => 1, // refuse les mots de passe faibles
        'two_factor'          => 1,   // double authentification TOTP (enrôlement par utilisateur)

        // ── Alertes temps réel (A) ──
        'alerts_enabled'        => 0,
        'alerts_email'          => '',   // destinataire (vide = admin_email)
        'alerts_slack_webhook'  => '',   // URL webhook Slack/Discord/Teams
        'alerts_min_severity'   => 3,    // 1..4 — seuil de gravité minimal
        'alerts_throttle_min'   => 15,   // throttle par (canal+menace), en minutes

        // ── Anti-IDOR no-code (B) ──
        'idor_enabled'          => 0,
    ];
}

/**
 * Activation : crée la table de logs + options par défaut.
 */
function keyso_waf_activate(): void
{
    global $wpdb;
    $table   = $wpdb->prefix . KEYSO_WAF_TABLE;
    $charset = $wpdb->get_charset_collate();

    $sql = "CREATE TABLE {$table} (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        ip VARCHAR(45) NOT NULL DEFAULT '',
        method VARCHAR(10) NOT NULL DEFAULT '',
        path TEXT NULL,
        threat VARCHAR(64) NOT NULL DEFAULT '',
        detail TEXT NULL,
        action VARCHAR(20) NOT NULL DEFAULT 'block',
        user_agent TEXT NULL,
        PRIMARY KEY (id),
        KEY idx_created (created_at),
        KEY idx_ip (ip),
        KEY idx_threat (threat)
    ) {$charset};";

    require_once ABSPATH . 'wp-admin/includes/upgrade.php';
    dbDelta($sql);

    if (get_option('keyso_waf_options') === false) {
        add_option('keyso_waf_options', keyso_waf_default_options());
    }
}
register_activation_hook(__FILE__, 'keyso_waf_activate');

/**
 * Récupère les options fusionnées avec les valeurs par défaut.
 *
 * @return array<string,mixed>
 */
function keyso_waf_get_options(): array
{
    $saved = get_option('keyso_waf_options', []);
    return array_merge(keyso_waf_default_options(), is_array($saved) ? $saved : []);
}

// ── Bootstrap : démarrer le gardien tôt, sur toutes les requêtes ──
add_action('plugins_loaded', function () {
    $options = keyso_waf_get_options();
    if (empty($options['enabled'])) {
        return;
    }
    (new \KeysO_WAF\Guard($options))->boot();
}, 1);

// ── Admin (dashboard + réglages) ──────────────────────────────
if (is_admin()) {
    add_action('plugins_loaded', function () {
        (new \KeysO_WAF\Admin())->boot();
    }, 2);
    // Revalidation périodique de la licence (tolérante aux pannes réseau)
    add_action('admin_init', ['\KeysO_WAF\License', 'maybeRevalidate']);
}
