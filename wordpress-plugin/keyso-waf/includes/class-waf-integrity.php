<?php
/**
 * KeysO-WAF — Détection d'intrusion & durcissement transport.
 *
 * Un plugin ne peut PAS empêcher un serveur compromis ou un vol de base par
 * accès SSH ; mais il peut DÉTECTER les signes d'intrusion et durcir le
 * transport, ce qui réduit fortement l'impact :
 *
 *   • Altération de siteurl/home : signe n°1 de défacement / redirection
 *     malveillante post-compromission → alerte immédiate.
 *   • Liaison de session (optionnel) : un cookie admin volé et rejoué depuis
 *     une autre IP est détecté → déconnexion + alerte (anti-vol de session).
 *   • Forçage HTTPS admin + HSTS : protège les identifiants en transit.
 *   • Posture : alerte si PHP en fin de vie ou WordPress core obsolète
 *     (les versions obsolètes sont la porte d'entrée des zero-days connus).
 *
 * @package KeysO_WAF
 */

namespace KeysO_WAF;

if (!defined('ABSPATH')) exit;

final class Integrity
{
    /** @var array<string,mixed> */
    private array $opt;

    public function __construct(array $options)
    {
        $this->opt = $options;
    }

    public function boot(): void
    {
        if (!empty($this->opt['detect_siteurl_tamper'])) {
            add_filter('pre_update_option_siteurl', [$this, 'onUrlChange'], 10, 2);
            add_filter('pre_update_option_home', [$this, 'onUrlChange'], 10, 2);
        }
        if (!empty($this->opt['force_ssl_admin'])) {
            if (!defined('FORCE_SSL_ADMIN')) define('FORCE_SSL_ADMIN', true);
            add_action('send_headers', [$this, 'hsts']);
        }
        if (!empty($this->opt['session_binding'])) {
            add_action('wp_login', [$this, 'bindSession'], 10, 2);
            add_action('init', [$this, 'verifySession'], 1);
        }
        if (!empty($this->opt['posture_alerts']) && function_exists('is_admin') && is_admin()) {
            add_action('admin_notices', [$this, 'postureNotice']);
        }
    }

    // ── Altération de l'URL du site (défacement / hijack) ──
    public function onUrlChange($value, $old)
    {
        if ((string) $value !== (string) $old) {
            Logger::log([
                'ip' => Guard::staticClientIp(), 'method' => $_SERVER['REQUEST_METHOD'] ?? '',
                'path' => ($_SERVER['REQUEST_URI'] ?? '') . ' [integrity]', 'threat' => 'business_logic',
                'detail' => "ALERTE : URL du site modifiée « {$old} » → « {$value} » (signe de compromission)",
                'action' => 'monitor', 'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
            ]);
        }
        return $value;
    }

    // ── HSTS (transport) ──
    public function hsts(): void
    {
        if (is_ssl()) {
            header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
        }
    }

    // ── Liaison de session (anti vol de cookie) ──
    public function bindSession($user_login, $user): void
    {
        if ($user instanceof \WP_User) {
            update_user_meta($user->ID, 'keyso_session_ip', Guard::staticClientIp());
        }
    }

    public function verifySession(): void
    {
        if (!function_exists('is_user_logged_in') || !is_user_logged_in()) return;
        $uid = get_current_user_id();
        if (!$uid) return;
        // Ne contraindre que les comptes à privilèges (limite les faux positifs)
        if (!user_can($uid, 'edit_others_posts')) return;

        $bound = (string) get_user_meta($uid, 'keyso_session_ip', true);
        if ($bound === '') return;
        $now = Guard::staticClientIp();
        if ($now !== $bound && $now !== '0.0.0.0') {
            Logger::log([
                'ip' => $now, 'method' => $_SERVER['REQUEST_METHOD'] ?? '',
                'path' => ($_SERVER['REQUEST_URI'] ?? '') . ' [session]', 'threat' => 'business_logic',
                'detail' => "Session privilégiée rejouée depuis une IP différente ({$bound} → {$now}) — possible vol de cookie. Déconnexion.",
                'action' => 'block', 'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
            ]);
            wp_logout();
            wp_safe_redirect(wp_login_url());
            exit;
        }
    }

    // ── Posture de sécurité ──
    public function postureNotice(): void
    {
        if (!current_user_can('manage_options')) return;
        $warnings = [];
        if (version_compare(PHP_VERSION, '8.1', '<')) {
            $warnings[] = sprintf(__('PHP %s est en fin de vie (sécurité non maintenue). Mettez à niveau vers PHP 8.2+.', 'keyso-waf'), PHP_VERSION);
        }
        if (function_exists('get_bloginfo')) {
            global $wp_version;
            if (function_exists('get_preferred_from_update_core')) {
                $core = function_exists('get_site_transient') ? get_site_transient('update_core') : null;
                if ($core && !empty($core->updates) && ($core->updates[0]->response ?? '') === 'upgrade') {
                    $warnings[] = __('WordPress core n\'est pas à jour — appliquez la mise à jour (les versions obsolètes exposent aux failles connues).', 'keyso-waf');
                }
            }
        }
        if (!is_ssl() && empty($this->opt['force_ssl_admin'])) {
            $warnings[] = __('Le site ne semble pas en HTTPS — activez le forçage HTTPS admin (Réglages KeysO-WAF) et un certificat TLS.', 'keyso-waf');
        }
        foreach ($warnings as $w) {
            echo '<div class="notice notice-warning"><p>🛡️ <strong>KeysO-WAF</strong> : ' . esc_html($w) . '</p></div>';
        }
    }
}
