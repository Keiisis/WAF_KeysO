<?php
/**
 * KeysO-WAF — Scanner profond des entrées (XSS + SQLi POST + admin-ajax).
 *
 * Complète le BodyScanner (structurel) et le module Hardening (SQLi sur GET) :
 *   • XSS : détecte <script>, gestionnaires on*, javascript:, <iframe>/<svg> etc.
 *     dans les paramètres GET et POST.
 *   • SQLi sur POST : optionnel (réutilise Hardening::looksLikeSqli).
 *   • Couvre aussi admin-ajax.php (action + paramètres).
 *
 * Anti-faux-positif : les utilisateurs autorisés à publier du HTML (capacité
 * unfiltered_html : admins/éditeurs) sont EXEMPTÉS du scan POST — eux écrivent
 * légitimement du <script>/<iframe> dans le contenu. Le scan POST ne vise donc
 * que les soumissions d'utilisateurs non privilégiés (commentaires, formulaires).
 *
 * @package KeysO_WAF
 */

namespace KeysO_WAF;

if (!defined('ABSPATH')) exit;

final class DeepScan
{
    /** @var array<string,mixed> */
    private array $opt;

    /** Vecteurs XSS haute-confiance (faible taux de faux positifs). */
    private const XSS = [
        '/<script\b/i',
        '/<\/script>/i',
        '/javascript:\s*\S/i',
        '/\bon(?:error|load|click|mouseover|focus|submit|toggle|animationstart)\s*=/i',
        '/<iframe\b/i',
        '/<svg\b[^>]*\bon\w+\s*=/i',
        '/<img[^>]+\bon\w+\s*=/i',
        '/document\s*\.\s*cookie/i',
        '/<body[^>]+\bon\w+\s*=/i',
        '/\bdata:text\/html/i',
    ];

    public function __construct(array $options)
    {
        $this->opt = $options;
    }

    public function boot(): void
    {
        // 'init' couvre les requêtes front ET admin-ajax (DOING_AJAX passe par init)
        add_action('init', [$this, 'scan'], 1);
    }

    public function scan(): void
    {
        // GET : toujours scanné (une URL contient rarement du HTML/JS légitime)
        $getVals = [];
        $get = function_exists('wp_unslash') ? wp_unslash($_GET) : $_GET;
        $this->collect($get, $getVals);
        foreach ($getVals as $v) {
            if ($this->looksLikeXss($v)) {
                $this->block('xss', 'xss', 'Payload XSS (GET) : ' . substr($v, 0, 140));
            }
        }

        // POST : exempté pour les utilisateurs pouvant publier du HTML (unfiltered_html)
        if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST' || empty($_POST)) {
            return;
        }
        if (function_exists('current_user_can') && current_user_can('unfiltered_html')) {
            return; // admin/éditeur : écrit du HTML légitimement
        }
        $postVals = [];
        $post = function_exists('wp_unslash') ? wp_unslash($_POST) : $_POST;
        $this->collect($post, $postVals);
        foreach ($postVals as $v) {
            if ($this->looksLikeXss($v)) {
                $this->block('xss', 'xss', 'Payload XSS (POST) : ' . substr($v, 0, 140));
            }
            if (!empty($this->opt['sqli_post']) && class_exists('\KeysO_WAF\Hardening') && Hardening::looksLikeSqli($v)) {
                $this->block('sqli', 'sql_injection', 'Payload SQLi (POST) : ' . substr($v, 0, 140));
            }
        }
    }

    /** Une valeur contient-elle un vecteur XSS ? (testable unitairement) */
    public static function looksLikeXss(string $value): bool
    {
        if (strlen($value) < 4) return false;
        foreach (self::XSS as $rx) {
            if (preg_match($rx, $value)) return true;
        }
        return false;
    }

    private function collect($node, array &$out): void
    {
        if (is_scalar($node)) {
            $out[] = (string) $node;
        } elseif (is_array($node)) {
            foreach ($node as $v) $this->collect($v, $out);
        }
    }

    private function block(string $surface, string $threat, string $detail): void
    {
        Logger::log([
            'ip' => Guard::staticClientIp(), 'method' => $_SERVER['REQUEST_METHOD'] ?? '',
            'path' => ($_SERVER['REQUEST_URI'] ?? '') . " [{$surface}]", 'threat' => $threat,
            'detail' => $detail, 'action' => 'block', 'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
        ]);
        $msg = trim((string)($this->opt['block_message'] ?? ''));
        status_header(403);
        nocache_headers();
        wp_die(esc_html($msg !== '' ? $msg : __('Requête bloquée par le pare-feu applicatif.', 'keyso-waf')),
            esc_html__('Requête refusée', 'keyso-waf'), ['response' => 403]);
    }
}
