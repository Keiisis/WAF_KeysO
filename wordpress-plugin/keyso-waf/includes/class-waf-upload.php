<?php
/**
 * KeysO-WAF — Scanner d'uploads (anti web-shell).
 *
 * Intercepte chaque fichier uploadé (médiathèque, formulaires) AVANT son
 * enregistrement et refuse :
 *   • extensions exécutables (.php, .phtml, .phar, .sh, .cgi…), y compris
 *     masquées en double extension (shell.php.jpg) ;
 *   • code PHP embarqué dans un fichier (même déclaré comme image) ;
 *   • polyglotes : magic bytes d'image mais contenu script exécutable ;
 *   • incohérence entre l'extension/MIME déclaré et la signature réelle.
 *
 * Porté du cœur SDK (upload-scanner). 100% PHP, sans dépendance.
 *
 * @package KeysO_WAF
 */

namespace KeysO_WAF;

if (!defined('ABSPATH')) exit;

final class Upload
{
    private const DANGEROUS_EXT = [
        'php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phtml', 'phps', 'pht', 'phar',
        'cgi', 'pl', 'py', 'sh', 'bash', 'asp', 'aspx', 'jsp', 'jspx', 'exe', 'dll',
        'so', 'htaccess', 'htm', 'shtml',
    ];

    public function boot(): void
    {
        add_filter('wp_handle_upload_prefilter', [$this, 'scan']);
    }

    /** @param array<string,mixed> $file */
    public function scan($file)
    {
        $name = strtolower((string)($file['name'] ?? ''));
        if ($name === '') return $file;

        // 1. Extension exécutable — à N'IMPORTE QUELLE position (double extension)
        $parts = explode('.', $name);
        for ($i = 1, $n = count($parts); $i < $n; $i++) {
            if (in_array($parts[$i], self::DANGEROUS_EXT, true)) {
                return $this->reject($file, $name, 'dangerous_extension', "Extension exécutable .{$parts[$i]}");
            }
        }

        // 2. Analyse du contenu (premiers Ko)
        $tmp = (string)($file['tmp_name'] ?? '');
        if ($tmp !== '' && is_readable($tmp)) {
            $head = (string) @file_get_contents($tmp, false, null, 0, 8192);
            if ($head !== '') {
                if (preg_match('/<\?php|<\?=/i', $head)) {
                    return $this->reject($file, $name, 'embedded_php', 'Code PHP embarqué dans le fichier');
                }
                $real = $this->magic($head);
                // Polyglote : signature image/PDF mais contient du code exécutable
                if ($real !== null && preg_match('/<\?php|<script\b|base64_decode\s*\(|eval\s*\(|system\s*\(|passthru\s*\(/i', $head)) {
                    return $this->reject($file, $name, 'polyglot', "Polyglote : signature {$real} mais code exécutable embarqué");
                }
                // Incohérence : déclaré image mais signature absente/différente
                $declared = strtolower((string)($file['type'] ?? ''));
                if (strpos($declared, 'image/') === 0 && $real === null && preg_match('/<\?|<script\b|<html|#!\//i', $head)) {
                    return $this->reject($file, $name, 'mime_mismatch', "MIME déclaré « {$declared} » mais contenu non-image");
                }
            }
        }
        return $file;
    }

    /** Détecte le type réel via magic bytes. */
    private function magic(string $head): ?string
    {
        $b = static function (string $s, array $sig): bool {
            foreach ($sig as $i => $byte) {
                if (!isset($s[$i]) || ord($s[$i]) !== $byte) return false;
            }
            return true;
        };
        if ($b($head, [0xFF, 0xD8, 0xFF])) return 'jpeg';
        if ($b($head, [0x89, 0x50, 0x4E, 0x47])) return 'png';
        if ($b($head, [0x47, 0x49, 0x46, 0x38])) return 'gif';
        if (strncmp($head, 'RIFF', 4) === 0 && strpos($head, 'WEBP') !== false) return 'webp';
        if (strncmp($head, '%PDF', 4) === 0) return 'pdf';
        return null;
    }

    /** @param array<string,mixed> $file */
    private function reject(array $file, string $name, string $threat, string $detail)
    {
        Logger::log([
            'ip' => Guard::staticClientIp(), 'method' => $_SERVER['REQUEST_METHOD'] ?? '',
            'path' => 'upload:' . substr($name, 0, 120) . ' [upload]', 'threat' => $threat,
            'detail' => $detail, 'action' => 'block', 'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
        ]);
        $msg = trim((string)(keyso_waf_get_options()['block_message'] ?? ''));
        $file['error'] = $msg !== '' ? $msg : __('Fichier refusé par le pare-feu (type ou contenu dangereux).', 'keyso-waf');
        return $file;
    }
}
