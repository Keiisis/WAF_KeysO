<?php
/**
 * Plugin Name:       KeysO-WAF — Pare-feu applicatif surpuissant
 * Plugin URI:        https://github.com/Keiisis/WAF_KeysO
 * Description:        WAF nouvelle génération : analyse structurelle des payloads (Prototype Pollution, RCE, SSRF, DoS), autorisation au niveau objet (anti-IDOR/BOLA), protection brute-force, rate-limiting, honeypot et journal de sécurité. Léger, sans dépendance externe.
 * Version:           1.0.0
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

define('KEYSO_WAF_VERSION', '1.0.0');
define('KEYSO_WAF_FILE', __FILE__);
define('KEYSO_WAF_DIR', plugin_dir_path(__FILE__));
define('KEYSO_WAF_URL', plugin_dir_url(__FILE__));
define('KEYSO_WAF_TABLE', 'keyso_waf_logs');

// ── Core portable (port PHP) ──────────────────────────────────
require_once KEYSO_WAF_DIR . 'includes/BodyScanner.php';
require_once KEYSO_WAF_DIR . 'includes/Ownership.php';

// ── Modules du plugin ─────────────────────────────────────────
require_once KEYSO_WAF_DIR . 'includes/class-waf-logger.php';
require_once KEYSO_WAF_DIR . 'includes/class-waf-rate-limit.php';
require_once KEYSO_WAF_DIR . 'includes/class-waf-guard.php';
require_once KEYSO_WAF_DIR . 'includes/class-waf-admin.php';

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
}
