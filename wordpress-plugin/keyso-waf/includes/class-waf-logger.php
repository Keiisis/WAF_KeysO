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
