<?php
/**
 * KeysO-WAF — Activation par clé de licence (anti-piratage).
 *
 * Vérifie une clé de licence contre un serveur de licences configurable.
 * Modèle ÉTHIQUE : la protection cœur (body scanner, brute-force, rate-limit,
 * honeypot, headers) reste TOUJOURS active — on ne désactive jamais la sécurité
 * d'un site faute de licence. Seules les fonctions PREMIUM (alertes temps réel,
 * anti-IDOR no-code) sont réservées aux licences valides.
 *
 * Serveur de licences : pointez la constante KEYSO_WAF_LICENSE_API (ou le filtre
 * 'keyso_waf_license_api') vers votre endpoint. Compatible avec n'importe quel
 * service renvoyant du JSON {"valid":true|false}. Un endpoint d'exemple peut
 * être déployé en quelques lignes (Vercel/Cloudflare Worker/PHP).
 *
 * @package KeysO_WAF
 */

namespace KeysO_WAF;

if (!defined('ABSPATH')) exit;

final class License
{
    public const OPT_KEY    = 'keyso_waf_license_key';
    public const OPT_STATUS = 'keyso_waf_license_status'; // 'valid' | 'invalid' | 'inactive'
    public const OPT_EXPIRY = 'keyso_waf_license_expiry';
    private const RECHECK_T = 'keyso_waf_license_recheck';

    /** URL du serveur de licences (vide = mode communautaire, premium off). */
    public static function apiUrl(): string
    {
        $default = defined('KEYSO_WAF_LICENSE_API') ? (string) KEYSO_WAF_LICENSE_API : '';
        return esc_url_raw((string) apply_filters('keyso_waf_license_api', $default));
    }

    public static function key(): string
    {
        return trim((string) get_option(self::OPT_KEY, ''));
    }

    public static function status(): string
    {
        return (string) get_option(self::OPT_STATUS, 'inactive');
    }

    /** Fonctions premium débloquées ? (protection cœur indépendante de ceci). */
    public static function isPro(): bool
    {
        return self::status() === 'valid';
    }

    /** Appelle le serveur de licences. @return array{ok:bool,valid:bool,message:string,expiry?:string} */
    private static function call(string $action, string $key): array
    {
        $api = self::apiUrl();
        if ($api === '') {
            return ['ok' => false, 'valid' => false, 'message' => __('Aucun serveur de licence configuré (constante KEYSO_WAF_LICENSE_API).', 'keyso-waf')];
        }
        $res = wp_remote_post($api, [
            'timeout' => 12,
            'headers' => ['Content-Type' => 'application/json', 'Accept' => 'application/json'],
            'body'    => wp_json_encode([
                'action'  => $action,                 // 'activate' | 'deactivate' | 'check'
                'key'     => $key,
                'domain'  => self::domain(),
                'product' => 'keyso-waf',
                'version' => defined('KEYSO_WAF_VERSION') ? KEYSO_WAF_VERSION : '',
            ]),
        ]);
        if (is_wp_error($res)) {
            return ['ok' => false, 'valid' => false, 'message' => $res->get_error_message()];
        }
        $code = (int) wp_remote_retrieve_response_code($res);
        $data = json_decode((string) wp_remote_retrieve_body($res), true);
        if ($code < 200 || $code >= 300 || !is_array($data)) {
            return ['ok' => false, 'valid' => false, 'message' => sprintf(__('Réponse serveur invalide (HTTP %d).', 'keyso-waf'), $code)];
        }
        return [
            'ok'      => true,
            'valid'   => !empty($data['valid']),
            'message' => isset($data['message']) ? sanitize_text_field((string) $data['message']) : '',
            'expiry'  => isset($data['expiry']) ? sanitize_text_field((string) $data['expiry']) : '',
        ];
    }

    /** Active une clé. @return array{success:bool,message:string} */
    public static function activate(string $rawKey): array
    {
        $key = sanitize_text_field($rawKey);
        if ($key === '') {
            return ['success' => false, 'message' => __('Veuillez saisir une clé de licence.', 'keyso-waf')];
        }
        $r = self::call('activate', $key);
        update_option(self::OPT_KEY, $key);
        if (!$r['ok']) {
            update_option(self::OPT_STATUS, 'inactive');
            return ['success' => false, 'message' => $r['message']];
        }
        if ($r['valid']) {
            update_option(self::OPT_STATUS, 'valid');
            if (!empty($r['expiry'])) update_option(self::OPT_EXPIRY, $r['expiry']);
            set_transient(self::RECHECK_T, 1, DAY_IN_SECONDS);
            return ['success' => true, 'message' => __('Licence activée — fonctions premium débloquées.', 'keyso-waf')];
        }
        update_option(self::OPT_STATUS, 'invalid');
        return ['success' => false, 'message' => $r['message'] ?: __('Clé invalide ou déjà utilisée sur un autre domaine.', 'keyso-waf')];
    }

    /** Désactive la licence pour ce domaine. */
    public static function deactivate(): array
    {
        $key = self::key();
        if ($key !== '') self::call('deactivate', $key);
        update_option(self::OPT_STATUS, 'inactive');
        delete_option(self::OPT_EXPIRY);
        delete_transient(self::RECHECK_T);
        return ['success' => true, 'message' => __('Licence désactivée sur ce domaine.', 'keyso-waf')];
    }

    /** Revalidation périodique (1×/jour) — déclenchée sur admin_init. */
    public static function maybeRevalidate(): void
    {
        if (self::status() !== 'valid') return;
        if (get_transient(self::RECHECK_T)) return;          // déjà vérifié récemment
        set_transient(self::RECHECK_T, 1, DAY_IN_SECONDS);
        $r = self::call('check', self::key());
        // Tolérance panne réseau : on ne révoque QUE sur réponse explicite "invalide"
        if ($r['ok'] && !$r['valid']) {
            update_option(self::OPT_STATUS, 'invalid');
        } elseif ($r['ok'] && $r['valid']) {
            update_option(self::OPT_STATUS, 'valid');
            if (!empty($r['expiry'])) update_option(self::OPT_EXPIRY, $r['expiry']);
        }
    }

    private static function domain(): string
    {
        $host = wp_parse_url(home_url('/'), PHP_URL_HOST);
        return is_string($host) ? $host : '';
    }
}
