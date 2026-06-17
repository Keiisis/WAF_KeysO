<?php
/**
 * KeysO-WAF — Durcissement WordPress (SQLi, énumération, intégrité base).
 *
 * Couche de protection complémentaire au gardien :
 *   • Détection d'injection SQL dans les paramètres GET / la query string
 *     (bloque le SQL malveillant AVANT qu'il atteigne la base de données).
 *   • Anti-énumération des utilisateurs (?author=N, REST /wp/v2/users) —
 *     empêche un attaquant de récolter les identifiants à attaquer.
 *   • Messages de login GÉNÉRIQUES (ne révèle pas si un identifiant existe).
 *   • Désactivation optionnelle de XML-RPC (vecteur brute-force / pingback DDoS).
 *   • Surveillance d'INTÉGRITÉ : alerte lorsqu'un compte administrateur est
 *     créé ou qu'un utilisateur est élevé en admin (persistance post-intrusion).
 *
 * NB : les mots de passe WordPress sont stockés hachés (phpass/bcrypt salés) ;
 * ils ne peuvent pas être « récupérés » en clair. Ce module réduit la capacité
 * d'un attaquant à cibler et à persister, il ne remplace pas HTTPS.
 *
 * @package KeysO_WAF
 */

namespace KeysO_WAF;

if (!defined('ABSPATH')) exit;

final class Hardening
{
    /** @var array<string,mixed> */
    private array $opt;

    /** Signatures SQLi haute-confiance (scannées sur les VALEURS de paramètres). */
    private const SQLI = [
        '/\bunion\b[\s\S]{0,40}\bselect\b/i',
        '/\bselect\b[\s\S]{0,80}\bfrom\b[\s\S]{0,60}\b(information_schema|users|wp_users|pg_)/i',
        '/\b(or|and)\b\s*\d+\s*=\s*\d+(\s|--|#|$)/i',          // ' OR 1=1
        "/'\\s*(or|and)\\s+'?\\d/i",                             // ' or '1
        '/\b(sleep|benchmark|pg_sleep)\s*\(/i',                  // time-based
        '/\bwaitfor\s+delay\b/i',
        '/\b(load_file|into\s+(out|dump)file|information_schema\.)/i',
        '/\bupdatexml\s*\(|\bextractvalue\s*\(/i',               // error-based
        '/;\s*(drop|insert|update|delete|alter|create)\s+/i',    // stacked queries
    ];

    public function __construct(array $options)
    {
        $this->opt = $options;
    }

    public function boot(): void
    {
        if (!empty($this->opt['sqli_detection'])) {
            add_action('init', [$this, 'checkSqli'], 1);
        }
        if (!empty($this->opt['block_user_enum'])) {
            add_action('init', [$this, 'blockAuthorScan'], 1);
            add_filter('rest_endpoints', [$this, 'restrictUsersEndpoint']);
            add_filter('rest_pre_dispatch', [$this, 'blockUsersRest'], 4, 3);
            // Coupe les fuites de noms via oEmbed / sitemap auteurs
            add_filter('rest_user_query', '__return_empty_array');
        }
        if (!empty($this->opt['generic_login_errors'])) {
            add_filter('login_errors', static function () {
                return __('Identifiants invalides. Vérifiez vos informations.', 'keyso-waf');
            });
        }
        if (!empty($this->opt['disable_xmlrpc'])) {
            add_filter('xmlrpc_enabled', '__return_false');
            add_filter('xmlrpc_methods', '__return_empty_array');
            add_action('init', [$this, 'blockXmlrpc'], 1);
        }
        if (!empty($this->opt['db_integrity_alerts'])) {
            add_action('set_user_role', [$this, 'onRoleChange'], 10, 3);
            add_action('user_register', [$this, 'onUserRegister'], 10, 1);
        }
        if (!empty($this->opt['enforce_strong_passwords'])) {
            add_action('user_profile_update_errors', [$this, 'validateProfilePassword'], 10, 1);
            add_action('validate_password_reset', [$this, 'validateResetPassword'], 10, 2);
        }
    }

    // ── Mots de passe forts (tue le cassage par dictionnaire à la source) ──
    private const COMMON_PASSWORDS = [
        'password', 'password1', 'password123', '123456', '12345678', '123456789',
        'qwerty', 'azerty', 'admin', 'admin123', 'letmein', 'welcome', 'monkey',
        'iloveyou', 'motdepasse', 'azertyuiop', 'qwertyuiop', 'changeme', 'secret',
        'root', 'toor', 'pass', 'test', 'guest', 'wordpress', 'soleil', 'bonjour',
    ];

    /** Un mot de passe est-il faible ? (testable unitairement) */
    public static function isWeakPassword(string $pwd, string $username = ''): bool
    {
        if (strlen($pwd) < 12) return true;
        $low = strtolower($pwd);
        if (in_array($low, self::COMMON_PASSWORDS, true)) return true;
        if ($username !== '' && stripos($pwd, $username) !== false) return true;
        // Au moins 3 classes de caractères sur 4 (minuscule/majuscule/chiffre/symbole)
        $classes = 0;
        if (preg_match('/[a-z]/', $pwd)) $classes++;
        if (preg_match('/[A-Z]/', $pwd)) $classes++;
        if (preg_match('/\d/', $pwd))    $classes++;
        if (preg_match('/[^a-zA-Z0-9]/', $pwd)) $classes++;
        return $classes < 3;
    }

    private const PWD_HINT = 'Mot de passe trop faible : au moins 12 caractères, mêlant majuscules, minuscules, chiffres et symboles, et différent de votre identifiant.';

    public function validateProfilePassword($errors): void
    {
        $pwd = isset($_POST['pass1']) ? (string) $_POST['pass1'] : '';
        if ($pwd === '') return; // pas de changement de mot de passe
        $login = isset($_POST['user_login']) ? sanitize_user(wp_unslash($_POST['user_login'])) : '';
        if (self::isWeakPassword($pwd, $login) && method_exists($errors, 'add')) {
            $errors->add('keyso_weak_pwd', __(self::PWD_HINT, 'keyso-waf'));
        }
    }

    public function validateResetPassword($errors, $user): void
    {
        $pwd = isset($_POST['pass1']) ? (string) $_POST['pass1'] : '';
        if ($pwd === '') return;
        $login = ($user && !is_wp_error($user)) ? (string) $user->user_login : '';
        if (self::isWeakPassword($pwd, $login) && method_exists($errors, 'add')) {
            $errors->add('keyso_weak_pwd', __(self::PWD_HINT, 'keyso-waf'));
        }
    }

    // ── Détection SQLi (valeurs GET + query string décodée) ──
    public function checkSqli(): void
    {
        $candidates = [];
        // wp_unslash : WordPress ajoute des slashes magiques à $_GET ('→\'),
        // ce qui masquerait les payloads SQLi à base de guillemets. On scanne
        // donc les valeurs dé-slashées.
        $get = function_exists('wp_unslash') ? wp_unslash($_GET) : $_GET;
        foreach ((array) $get as $v) {
            $this->collectScalars($v, $candidates);
        }
        // Query string brute décodée (attrape les formes encodées)
        $qs = (string) ($_SERVER['QUERY_STRING'] ?? '');
        if ($qs !== '') {
            $candidates[] = rawurldecode(rawurldecode($qs));
        }
        foreach ($candidates as $value) {
            if (self::looksLikeSqli($value)) {
                $this->block('sqli', 'sql_injection', 'Payload SQLi : ' . substr($value, 0, 160));
                status_header(403);
                nocache_headers();
                wp_die(esc_html($this->msg()), esc_html__('Requête refusée', 'keyso-waf'), ['response' => 403]);
            }
        }
    }

    /** Une valeur ressemble-t-elle à une injection SQL ? (testable unitairement) */
    public static function looksLikeSqli(string $value): bool
    {
        foreach (self::SQLI as $rx) {
            if (preg_match($rx, $value)) {
                return true;
            }
        }
        return false;
    }

    private function collectScalars($node, array &$out): void
    {
        if (is_scalar($node)) {
            $out[] = (string) $node;
        } elseif (is_array($node)) {
            foreach ($node as $v) {
                $this->collectScalars($v, $out);
            }
        }
    }

    // ── Anti-énumération : ?author=N ──
    public function blockAuthorScan(): void
    {
        if (is_admin() || is_user_logged_in()) {
            return;
        }
        $author = $_GET['author'] ?? null;
        if ($author !== null && preg_match('/^\d+$/', (string) $author)) {
            $this->block('enum', 'enumeration', 'Author scan : ?author=' . (string) $author);
            status_header(403);
            wp_die(esc_html($this->msg()), esc_html__('Requête refusée', 'keyso-waf'), ['response' => 403]);
        }
    }

    /** Retire l'endpoint REST /wp/v2/users pour les visiteurs non connectés. */
    public function restrictUsersEndpoint($endpoints)
    {
        if (is_user_logged_in()) {
            return $endpoints;
        }
        foreach (array_keys($endpoints) as $route) {
            if (strpos($route, '/wp/v2/users') === 0) {
                unset($endpoints[$route]);
            }
        }
        return $endpoints;
    }

    /** Filet supplémentaire : refuse /wp/v2/users en lecture anonyme. */
    public function blockUsersRest($result, $server, $request)
    {
        if ($result !== null) {
            return $result;
        }
        $route = (string) $request->get_route();
        if (strpos($route, '/wp/v2/users') === 0 && !is_user_logged_in()) {
            $this->block('enum', 'enumeration', 'REST users (anonyme) : ' . $route);
            return new \WP_Error('keyso_waf_enum', __('Accès non autorisé.', 'keyso-waf'), ['status' => 401]);
        }
        return $result;
    }

    public function blockXmlrpc(): void
    {
        $uri = strtolower((string) ($_SERVER['REQUEST_URI'] ?? ''));
        if (strpos($uri, 'xmlrpc.php') !== false) {
            $this->block('xmlrpc', 'protocol_anomaly', 'Accès XML-RPC bloqué');
            status_header(403);
            wp_die(esc_html($this->msg()), esc_html__('Requête refusée', 'keyso-waf'), ['response' => 403]);
        }
    }

    // ── Intégrité : élévation / création d'administrateur ──
    public function onRoleChange($user_id, $role, $old_roles): void
    {
        if ($role === 'administrator' && !in_array('administrator', (array) $old_roles, true)) {
            $this->integrityAlert("Élévation en ADMINISTRATEUR de l'utilisateur #{$user_id}");
        }
    }

    public function onUserRegister($user_id): void
    {
        $u = function_exists('get_userdata') ? get_userdata($user_id) : null;
        if ($u && in_array('administrator', (array) $u->roles, true)) {
            $this->integrityAlert("Création d'un compte ADMINISTRATEUR #{$user_id} ({$u->user_login})");
        }
    }

    private function integrityAlert(string $detail): void
    {
        Logger::log([
            'ip'         => Guard::staticClientIp(),
            'method'     => $_SERVER['REQUEST_METHOD'] ?? '',
            'path'       => ($_SERVER['REQUEST_URI'] ?? '') . ' [integrity]',
            'threat'     => 'privilege_escalation',
            'detail'     => $detail,
            'action'     => 'monitor',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
        ]);
    }

    private function msg(): string
    {
        $custom = trim((string) ($this->opt['block_message'] ?? ''));
        return $custom !== '' ? $custom : __('Requête bloquée par le pare-feu applicatif.', 'keyso-waf');
    }

    private function block(string $surface, string $threat, string $detail): void
    {
        Logger::log([
            'ip'         => Guard::staticClientIp(),
            'method'     => $_SERVER['REQUEST_METHOD'] ?? '',
            'path'       => ($_SERVER['REQUEST_URI'] ?? '') . " [{$surface}]",
            'threat'     => $threat,
            'detail'     => $detail,
            'action'     => 'block',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
        ]);
    }
}
