<?php
/**
 * KeysO-WAF — Alertes temps réel (e-mail + Slack / webhook).
 *
 * Notifie l'admin lorsqu'une menace au-dessus d'un seuil de gravité est
 * bloquée. Throttling par (canal + type de menace) pour éviter le spam lors
 * d'une attaque en rafale.
 *
 * @package KeysO_WAF
 */

namespace KeysO_WAF;

if (!defined('ABSPATH')) exit;

final class Alerts
{
    /** Gravité par type de menace (1 = info … 4 = nuclear). */
    private const SEVERITY = [
        'prototype_pollution'  => 4,
        'rce_gadget'           => 4,
        'ssrf_internal_target' => 4,
        'idor'                 => 4,
        'php_object_injection' => 4,
        'brute_force'          => 3,
        'path_traversal'       => 3,
        'honeypot'             => 3,
        'array_explosion'      => 2,
        'key_explosion'        => 2,
        'recursive_depth'      => 2,
        'oversized_string'     => 2,
        'rate_limit'           => 1,
    ];

    /**
     * Évalue un événement et envoie une alerte si elle dépasse le seuil.
     *
     * @param array<string,mixed> $event {ip,threat,detail,path,method,...}
     */
    public static function maybeNotify(array $event): void
    {
        $opt = keyso_waf_get_options();
        if (empty($opt['alerts_enabled'])) {
            return;
        }

        $threat   = (string)($event['threat'] ?? 'unknown');
        $severity = self::SEVERITY[$threat] ?? 2;
        $minLevel = (int)($opt['alerts_min_severity'] ?? 3);
        if ($severity < $minLevel) {
            return;
        }

        // Throttle : 1 alerte par (canal+menace) par fenêtre configurée
        $window = max(60, (int)($opt['alerts_throttle_min'] ?? 15) * 60);

        $subject = sprintf('[KeysO-WAF] %s bloqué — %s', strtoupper($threat), self::siteHost());
        $lines = [
            '🛡️ KeysO-WAF a bloqué une menace.',
            '',
            'Type      : ' . $threat . ' (gravité ' . $severity . '/4)',
            'IP        : ' . (string)($event['ip'] ?? ''),
            'Méthode   : ' . (string)($event['method'] ?? ''),
            'Chemin    : ' . (string)($event['path'] ?? ''),
            'Détail    : ' . (string)($event['detail'] ?? ''),
            'User-Agent: ' . substr((string)($event['user_agent'] ?? ''), 0, 200),
            'Date      : ' . current_time('mysql'),
            'Site      : ' . home_url('/'),
        ];
        $body = implode("\n", $lines);

        // ── E-mail ──
        if (!empty($opt['alerts_email'])) {
            if (self::shouldSend('mail_' . $threat, $window)) {
                $to = sanitize_email((string)$opt['alerts_email']);
                if ($to && is_email($to)) {
                    wp_mail($to, $subject, $body);
                }
            }
        }

        // ── Slack / webhook ──
        if (!empty($opt['alerts_slack_webhook'])) {
            if (self::shouldSend('slack_' . $threat, $window)) {
                self::sendSlack((string)$opt['alerts_slack_webhook'], $threat, $severity, $event);
            }
        }
    }

    /** Throttle via transient : renvoie true si on peut envoyer (et arme la fenêtre). */
    private static function shouldSend(string $key, int $window): bool
    {
        $tkey = 'keyso_alert_' . md5($key);
        if (get_transient($tkey)) {
            return false;
        }
        set_transient($tkey, 1, $window);
        return true;
    }

    private static function sendSlack(string $webhook, string $threat, int $severity, array $event): void
    {
        $emoji = $severity >= 4 ? '🚨' : ($severity >= 3 ? '⚠️' : 'ℹ️');
        $payload = [
            'text' => sprintf('%s *KeysO-WAF* a bloqué `%s` sur %s', $emoji, $threat, self::siteHost()),
            'blocks' => [
                [
                    'type' => 'section',
                    'text' => [
                        'type' => 'mrkdwn',
                        'text' => sprintf(
                            "%s *Menace bloquée : `%s`* (gravité %d/4)\n*IP* : `%s`\n*Chemin* : `%s`\n*Détail* : %s",
                            $emoji, $threat, $severity,
                            (string)($event['ip'] ?? ''),
                            substr((string)($event['path'] ?? ''), 0, 120),
                            substr((string)($event['detail'] ?? ''), 0, 200)
                        ),
                    ],
                ],
            ],
        ];

        wp_remote_post($webhook, [
            'headers'  => ['Content-Type' => 'application/json'],
            'body'     => wp_json_encode($payload),
            'timeout'  => 5,
            'blocking' => false, // fire-and-forget : ne ralentit pas la requête bloquée
        ]);
    }

    private static function siteHost(): string
    {
        return (string) wp_parse_url(home_url('/'), PHP_URL_HOST);
    }
}
