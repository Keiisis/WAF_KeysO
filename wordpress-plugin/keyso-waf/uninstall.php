<?php
/**
 * KeysO-WAF — Nettoyage à la désinstallation.
 *
 * @package KeysO_WAF
 */

if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

global $wpdb;

// Supprimer la table de logs
$table = $wpdb->prefix . 'keyso_waf_logs';
$wpdb->query("DROP TABLE IF EXISTS {$table}");

// Supprimer les options
delete_option('keyso_waf_options');

// Purger les transients du plugin (rate-limit / lockout)
$wpdb->query(
    "DELETE FROM {$wpdb->options}
     WHERE option_name LIKE '\_transient\_keyso\_%'
        OR option_name LIKE '\_transient\_timeout\_keyso\_%'"
);
