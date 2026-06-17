<?php
/**
 * KeysO-WAF — Journal de sécurité (table custom).
 *
 * @package KeysO_WAF
 */

namespace KeysO_WAF;

if (!defined('ABSPATH')) exit;

final class Logger
{
    /** Insère un événement de sécurité dans la table de logs. */
    public static function log(array $event): void
    {
        global $wpdb;
        $table = $wpdb->prefix . KEYSO_WAF_TABLE;

        $wpdb->insert(
            $table,
            [
                'ip'         => substr((string)($event['ip'] ?? ''), 0, 45),
                'method'     => substr((string)($event['method'] ?? ''), 0, 10),
                'path'       => (string)($event['path'] ?? ''),
                'threat'     => substr((string)($event['threat'] ?? ''), 0, 64),
                'detail'     => (string)($event['detail'] ?? ''),
                'action'     => substr((string)($event['action'] ?? 'block'), 0, 20),
                'user_agent' => (string)($event['user_agent'] ?? ''),
            ],
            ['%s', '%s', '%s', '%s', '%s', '%s', '%s']
        );

        // Garde-fou : on ne laisse pas la table exploser (max ~10k lignes)
        $count = (int) $wpdb->get_var("SELECT COUNT(*) FROM {$table}");
        if ($count > 10000) {
            $wpdb->query("DELETE FROM {$table} ORDER BY id ASC LIMIT 2000");
        }

        // Alertes temps réel (e-mail / Slack) — throttlées, au-dessus d'un seuil
        if (class_exists('\KeysO_WAF\Alerts')) {
            Alerts::maybeNotify($event);
        }

        // Défense active : auto-ban d'une IP qui accumule des blocages
        if ((string)($event['action'] ?? '') === 'block') {
            self::recordViolation((string)($event['ip'] ?? ''));
        }
    }

    /** Incrémente le compteur de violations d'une IP ; auto-ban si seuil dépassé. */
    public static function recordViolation(string $ip): void
    {
        if ($ip === '' || $ip === '0.0.0.0') return;
        $o = function_exists('keyso_waf_get_options') ? keyso_waf_get_options() : [];
        if (empty($o['auto_ban_enabled'])) return;

        $threshold = max(3, (int)($o['auto_ban_threshold'] ?? 10));
        $window    = max(60, (int)($o['auto_ban_window'] ?? 600));
        $duration  = max(60, (int)($o['auto_ban_duration'] ?? 3600));

        $key = 'keyso_viol_' . md5($ip);
        $n = (int) get_transient($key) + 1;
        set_transient($key, $n, $window);
        if ($n >= $threshold) {
            set_transient('keyso_autoban_' . md5($ip), 1, $duration);
            delete_transient($key);
        }
    }

    /** L'IP est-elle auto-bannie ? (défense active) */
    public static function isAutoBanned(string $ip): bool
    {
        if ($ip === '' || $ip === '0.0.0.0') return false;
        return (bool) get_transient('keyso_autoban_' . md5($ip));
    }

    /** @return array<int,object> Les N derniers événements. */
    public static function recent(int $limit = 100): array
    {
        global $wpdb;
        $table = $wpdb->prefix . KEYSO_WAF_TABLE;
        $limit = max(1, min(500, $limit));
        return $wpdb->get_results(
            $wpdb->prepare("SELECT * FROM {$table} ORDER BY id DESC LIMIT %d", $limit)
        ) ?: [];
    }

    /** @return array<string,int> Comptage par type de menace (30 derniers jours). */
    public static function stats(): array
    {
        global $wpdb;
        $table = $wpdb->prefix . KEYSO_WAF_TABLE;
        $rows = $wpdb->get_results(
            "SELECT threat, COUNT(*) AS n FROM {$table}
             WHERE created_at > (NOW() - INTERVAL 30 DAY)
             GROUP BY threat ORDER BY n DESC"
        ) ?: [];
        $out = [];
        foreach ($rows as $r) {
            $out[(string)$r->threat] = (int)$r->n;
        }
        return $out;
    }
}
