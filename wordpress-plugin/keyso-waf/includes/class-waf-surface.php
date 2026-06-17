<?php
/**
 * KeysO-WAF — Durcissement des surfaces & limitation post-intrusion.
 *
 * WordPress expose bien plus que wp-login.php. Ce module couvre les autres
 * routes/surfaces attaquables et — surtout — limite ce qu'un attaquant peut
 * faire S'IL a déjà volé un compte admin (le « blast radius ») :
 *
 *   • Éditeur de fichiers thèmes/extensions désactivé → tue le vecteur RCE n°1
 *     post-intrusion (un admin volé ne peut plus injecter du PHP).
 *   • Verrou installation/upload d'extensions & thèmes (optionnel).
 *   • Application Passwords : bloqués pour les comptes 2FA (sinon ils
 *     contournent le second facteur via l'API REST en Basic Auth).
 *   • Liste blanche d'IP pour wp-admin / wp-login → un login volé est inutile
 *     depuis une IP non autorisée (défense ultime contre le vol d'identifiants).
 *   • Blocage des chemins sensibles (readme.html, *.sql, *.bak, debug.log,
 *     sauvegardes de wp-config, .git…) → info-disclosure & fuites de secrets.
 *   • Rate-limit de wp-cron.php (amplification DoS).
 *
 * @package KeysO_WAF
 */

namespace KeysO_WAF;

if (!defined('ABSPATH')) exit;

final class Surface
{
    /** @var array<string,mixed> */
    private array $opt;

    /** Chemins sensibles : info-disclosure, secrets, sauvegardes. */
    private const SENSITIVE = [
        '/readme.html', '/license.txt', '/wp-config.php.bak', '/wp-config.php.old',
        '/wp-config.php.save', '/wp-config.php.orig', '/wp-config.php~', '/wp-config.txt',
        '/.git/', '/.svn/', '/.env', '/composer.lock', '/composer.json',
        '/debug.log', '/wp-content/debug.log', '/error_log',
    ];
    private const SENSITIVE_EXT = ['sql', 'bak', 'old', 'orig', 'save', 'swp', 'tar', 'gz', 'zip'];

    public function __construct(array $options)
    {
        $this->opt = $options;
    }

    public function boot(): void
    {
        if (!empty($this->opt['disable_file_editor']) && !defined('DISALLOW_FILE_EDIT')) {
            define('DISALLOW_FILE_EDIT', true);
        }
        if (!empty($this->opt['lock_plugin_theme_install'])) {
            add_filter('map_meta_cap', [$this, 'denyInstallCaps'], 10, 2);
        }
        if (!empty($this->opt['restrict_app_passwords'])) {
            add_filter('wp_is_application_passwords_available_for_user', [$this, 'appPasswordsForUser'], 10, 2);
        }
        if (!empty($this->opt['protect_sensitive_paths'])) {
            add_action('init', [$this, 'blockSensitivePaths'], 0);
            // Fichiers STATIQUES (readme.html, license.txt, *.sql, *.bak…) servis
            // par le serveur avant PHP : seul un règlage .htaccess les bloque.
            add_action('admin_init', [$this, 'ensureHtaccess']);
        }
        if (trim((string)($this->opt['admin_ip_allowlist'] ?? '')) !== '') {
            add_action('init', [$this, 'enforceAdminAllowlist'], 0);
        }
        if (!empty($this->opt['rate_limit'])) {
            add_action('init', [$this, 'protectWpCron'], 1);
        }
    }

    // ── Verrou installation/upload/suppression d'extensions & thèmes ──
    public function denyInstallCaps($caps, $cap)
    {
        $blocked = [
            'install_plugins', 'install_themes', 'upload_plugins', 'upload_themes',
            'delete_plugins', 'delete_themes', 'edit_plugins', 'edit_themes',
        ];
        if (in_array($cap, $blocked, true)) {
            return ['do_not_allow'];
        }
        return $caps;
    }

    // ── Application Passwords : refusés pour les comptes 2FA ──
    public function appPasswordsForUser($available, $user)
    {
        if ($available && $user instanceof \WP_User && TwoFactor::isEnabledFor($user->ID)) {
            return false;
        }
        return $available;
    }

    // ── Blocage des chemins sensibles ──
    public function blockSensitivePaths(): void
    {
        $uri = strtolower(parse_url($_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH) ?: '');
        if ($uri === '' || $uri === '/') return;

        $hit = false;
        foreach (self::SENSITIVE as $p) {
            if (strpos($uri, $p) !== false) { $hit = true; break; }
        }
        if (!$hit) {
            $ext = strtolower((string) pathinfo($uri, PATHINFO_EXTENSION));
            if ($ext !== '' && in_array($ext, self::SENSITIVE_EXT, true)) $hit = true;
        }
        if ($hit) {
            Logger::log([
                'ip' => Guard::staticClientIp(), 'method' => $_SERVER['REQUEST_METHOD'] ?? '',
                'path' => substr($uri, 0, 200) . ' [sensitive]', 'threat' => 'scanner_detection',
                'detail' => 'Accès chemin sensible : ' . substr($uri, 0, 160),
                'action' => 'block', 'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
            ]);
            status_header(404);
            nocache_headers();
            wp_die(esc_html($this->blockMessage()), esc_html__('Introuvable', 'keyso-waf'), ['response' => 404]);
        }
    }

    // ── Liste blanche d'IP pour wp-admin / wp-login ──
    public function enforceAdminAllowlist(): void
    {
        $uri = strtolower((string) ($_SERVER['REQUEST_URI'] ?? ''));
        $isLogin = strpos($uri, 'wp-login.php') !== false;
        $isAdmin = strpos($uri, '/wp-admin') !== false;
        // Exemptions : AJAX/admin-post front + REST (utilisés par des visiteurs)
        if (strpos($uri, 'admin-ajax.php') !== false || strpos($uri, 'admin-post.php') !== false) return;
        if (!$isLogin && !$isAdmin) return;

        $allow = array_filter(array_map('trim', explode("\n", (string) $this->opt['admin_ip_allowlist'])));
        $ip = Guard::staticClientIp();
        if ($allow !== [] && !in_array($ip, $allow, true)) {
            Logger::log([
                'ip' => $ip, 'method' => $_SERVER['REQUEST_METHOD'] ?? '',
                'path' => substr($uri, 0, 120) . ' [admin-allowlist]', 'threat' => 'enumeration',
                'detail' => "Accès admin/login refusé pour IP non autorisée {$ip}",
                'action' => 'block', 'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
            ]);
            status_header(403);
            nocache_headers();
            wp_die(esc_html($this->blockMessage()), esc_html__('Accès refusé', 'keyso-waf'), ['response' => 403]);
        }
    }

    // ── Rate-limit de wp-cron.php (amplification DoS) ──
    public function protectWpCron(): void
    {
        $uri = strtolower((string) ($_SERVER['REQUEST_URI'] ?? ''));
        if (strpos($uri, 'wp-cron.php') === false) return;
        $ip = Guard::staticClientIp();
        if (RateLimit::hit("cron_{$ip}", 6, 60)) {  // > 6 hits/min = abus
            status_header(429);
            wp_die(esc_html__('Trop de requêtes.', 'keyso-waf'), '', ['response' => 429]);
        }
    }

    /**
     * Écrit des règles .htaccess (Apache) pour bloquer les fichiers STATIQUES
     * sensibles que PHP ne peut pas intercepter (servis directement par le
     * serveur). Idempotent via insert_with_markers. Sans effet sur nginx
     * (l'admin doit alors ajouter l'équivalent en configuration serveur).
     */
    public function ensureHtaccess(): void
    {
        if (stripos((string)($_SERVER['SERVER_SOFTWARE'] ?? ''), 'apache') === false) {
            return; // .htaccess n'a d'effet que sur Apache/LiteSpeed
        }
        if (!function_exists('get_home_path') || !function_exists('insert_with_markers')) {
            require_once ABSPATH . 'wp-admin/includes/file.php';
            require_once ABSPATH . 'wp-admin/includes/misc.php';
        }
        $file = get_home_path() . '.htaccess';
        if ((file_exists($file) && !is_writable($file)) || (!file_exists($file) && !is_writable(dirname($file)))) {
            return; // pas accessible en écriture : on s'abstient silencieusement
        }
        $rules = [
            '<FilesMatch "(?i)\.(sql|bak|old|orig|save|swp|log|tar|gz)$">',
            'Require all denied',
            '</FilesMatch>',
            '<FilesMatch "(?i)^(readme\.html|license\.txt|wp-config\.php~|xmlrpc\.php\.bak)$">',
            'Require all denied',
            '</FilesMatch>',
            'Options -Indexes',
        ];
        insert_with_markers($file, 'KeysO-WAF', $rules);
    }

    private function blockMessage(): string
    {
        $c = trim((string) ($this->opt['block_message'] ?? ''));
        return $c !== '' ? $c : __('Requête bloquée par le pare-feu applicatif.', 'keyso-waf');
    }
}
