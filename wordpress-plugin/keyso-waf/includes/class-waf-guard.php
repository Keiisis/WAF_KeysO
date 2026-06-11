<?php
/**
 * KeysO-WAF — Gardien : branche tous les hooks de protection WordPress.
 *
 * @package KeysO_WAF
 */

namespace KeysO_WAF;

use WafCore\BodyScanner;
use WafCore\Ownership;

if (!defined('ABSPATH')) exit;

final class Guard
{
    /** @var array<string,mixed> */
    private array $opt;

    /** Chemins pièges : un accès = comportement malveillant quasi certain. */
    private const HONEYPOT_PATHS = [
        '/.env', '/.git/config', '/wp-config.php.bak', '/wp-config.old',
        '/shell.php', '/c99.php', '/adminer.php', '/phpinfo.php',
        '/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php',
    ];

    public function __construct(array $options)
    {
        $this->opt = $options;
    }

    public function boot(): void
    {
        if ($this->isWhitelisted($this->clientIp())) {
            return; // IP de confiance : aucun contrôle de blocage
        }

        if (!empty($this->opt['security_headers'])) {
            add_action('send_headers', [$this, 'sendSecurityHeaders']);
        }
        if (!empty($this->opt['block_honeypot'])) {
            add_action('init', [$this, 'checkHoneypot'], 1);
        }
        if (!empty($this->opt['rate_limit'])) {
            add_action('init', [$this, 'checkRateLimit'], 2);
        }
        if (!empty($this->opt['scan_rest_bodies'])) {
            add_filter('rest_pre_dispatch', [$this, 'scanRestRequest'], 5, 3);
            add_action('admin_init', [$this, 'scanAdminAjaxBody'], 1);
        }
        if (!empty($this->opt['protect_login'])) {
            add_filter('authenticate', [$this, 'preAuthLockout'], 30, 1);
            add_action('wp_login_failed', [$this, 'onLoginFailed'], 10, 1);
            add_action('wp_login', [$this, 'onLoginSuccess'], 10, 2);
        }

        // ── Anti-IDOR no-code (B) ── règles pilotées depuis l'admin
        if (!empty($this->opt['idor_enabled'])) {
            (new IdorRules())->boot();
        }
    }

    // ── #2 — Analyse structurelle des requêtes REST ──────────────
    public function scanRestRequest($result, $server, $request)
    {
        // ne pas court-circuiter une erreur déjà présente
        if ($result !== null) {
            return $result;
        }
        $body = method_exists($request, 'get_json_params') ? $request->get_json_params() : null;
        if (is_array($body) && !empty($body)) {
            $verdict = BodyScanner::scan($body);
            if (!$verdict['safe']) {
                $this->block('rest', $verdict['threat'], $verdict['detail']);
                return new \WP_Error('keyso_waf_blocked', __('Requête invalide.', 'keyso-waf'), ['status' => 400]);
            }
        }
        return $result;
    }

    // ── #2 bis — admin-ajax / POST classiques ────────────────────
    public function scanAdminAjaxBody(): void
    {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST' || empty($_POST)) {
            return;
        }
        // On scanne la structure des données POST (clés + valeurs)
        // wp_unslash pour annuler le slashing WP avant analyse.
        $payload = wp_unslash($_POST);
        $verdict = BodyScanner::scan($payload);
        if (!$verdict['safe']) {
            $this->block('admin_ajax', $verdict['threat'], $verdict['detail']);
            wp_die(
                esc_html__('Requête bloquée par le pare-feu applicatif.', 'keyso-waf'),
                esc_html__('Requête invalide', 'keyso-waf'),
                ['response' => 400]
            );
        }
    }

    // ── Honeypot ──────────────────────────────────────────────────
    public function checkHoneypot(): void
    {
        $uri = strtolower(parse_url($_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH) ?: '');
        foreach (self::HONEYPOT_PATHS as $trap) {
            if ($uri === $trap || str_ends_with($uri, $trap)) {
                $this->block('honeypot', 'honeypot', "Accès au chemin piège : {$uri}");
                status_header(404);
                nocache_headers();
                wp_die(esc_html__('Introuvable.', 'keyso-waf'), '', ['response' => 404]);
            }
        }
        // Path traversal grossier
        if (strpos($uri, '../') !== false || strpos($uri, '..\\') !== false) {
            $this->block('path_traversal', 'path_traversal', "Path traversal : {$uri}");
            wp_die(esc_html__('Requête invalide.', 'keyso-waf'), '', ['response' => 400]);
        }
    }

    // ── Rate limiting global par IP ──────────────────────────────
    public function checkRateLimit(): void
    {
        $ip  = $this->clientIp();
        $max = (int) $this->opt['rate_limit_max'];
        $win = (int) $this->opt['rate_limit_window'];
        if (RateLimit::hit("req_{$ip}", $max, $win)) {
            $this->block('rate_limit', 'rate_limit', "Dépassement : > {$max} req / {$win}s");
            status_header(429);
            header('Retry-After: ' . $win);
            wp_die(esc_html__('Trop de requêtes. Réessayez plus tard.', 'keyso-waf'), '', ['response' => 429]);
        }
    }

    // ── Brute-force login ────────────────────────────────────────
    public function preAuthLockout($user)
    {
        $ip = $this->clientIp();
        if (RateLimit::isLoginLocked($ip)) {
            $this->block('login', 'brute_force', "Lockout login actif pour {$ip}");
            return new \WP_Error(
                'keyso_waf_locked',
                __('Trop de tentatives de connexion. Compte temporairement verrouillé.', 'keyso-waf')
            );
        }
        return $user;
    }

    public function onLoginFailed($username): void
    {
        RateLimit::registerFailedLogin(
            $this->clientIp(),
            (int) $this->opt['login_max_attempts'],
            (int) $this->opt['login_lockout_min']
        );
    }

    public function onLoginSuccess($user_login, $user): void
    {
        RateLimit::clearFailedLogin($this->clientIp());
    }

    // ── Security headers ─────────────────────────────────────────
    public function sendSecurityHeaders(): void
    {
        header('X-Content-Type-Options: nosniff');
        header('X-Frame-Options: SAMEORIGIN');
        header('Referrer-Policy: strict-origin-when-cross-origin');
        header('Permissions-Policy: geolocation=(), microphone=(), camera=()');
    }

    // ══════════════════════════════════════════════════════════════
    // Helper public : autorisation au niveau objet (anti-IDOR)
    // À appeler dans vos endpoints custom :
    //   KeysO_WAF\Guard::assertOwnership($resolver, $userId, 'post', $id)
    // ══════════════════════════════════════════════════════════════
    public static function assertOwnership(callable $resolver, string $userId, string $type, string $id, array $options = []): bool
    {
        $verdict = Ownership::verify($resolver, [
            'userId' => $userId, 'resourceType' => $type, 'resourceId' => $id,
        ], $options);
        if (!$verdict['allowed']) {
            Logger::log([
                'ip' => self::staticClientIp(), 'method' => $_SERVER['REQUEST_METHOD'] ?? '',
                'path' => $_SERVER['REQUEST_URI'] ?? '', 'threat' => 'idor',
                'detail' => $verdict['detail'], 'action' => 'block',
                'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
            ]);
        }
        return $verdict['allowed'];
    }

    // ── Utilitaires ──────────────────────────────────────────────
    private function block(string $surface, string $threat, string $detail): void
    {
        Logger::log([
            'ip'         => $this->clientIp(),
            'method'     => $_SERVER['REQUEST_METHOD'] ?? '',
            'path'       => ($_SERVER['REQUEST_URI'] ?? '') . " [{$surface}]",
            'threat'     => $threat,
            'detail'     => $detail,
            'action'     => 'block',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
        ]);
    }

    private function isWhitelisted(string $ip): bool
    {
        $list = array_filter(array_map('trim', explode("\n", (string)($this->opt['whitelist_ips'] ?? ''))));
        return in_array($ip, $list, true);
    }

    private function clientIp(): string
    {
        return self::staticClientIp();
    }

    public static function staticClientIp(): string
    {
        // Ordre de confiance — adapter selon votre reverse-proxy / CDN
        foreach (['HTTP_CF_CONNECTING_IP', 'HTTP_X_REAL_IP', 'HTTP_X_FORWARDED_FOR', 'REMOTE_ADDR'] as $h) {
            if (!empty($_SERVER[$h])) {
                $ip = trim(explode(',', $_SERVER[$h])[0]);
                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    return $ip;
                }
            }
        }
        return '0.0.0.0';
    }
}
