<?php
/**
 * KeysO-WAF — Authentification à deux facteurs (TOTP, RFC 6238).
 *
 * Ajoute un second facteur au login WordPress, compatible Google Authenticator,
 * Authy, Microsoft Authenticator, etc. Implémentation TOTP 100% PHP, SANS
 * dépendance externe (aucun secret n'est envoyé à un tiers).
 *
 * Pourquoi c'est décisif : même si un attaquant DEVINE (brute-force en ligne)
 * ou CASSE (dictionnaire hors-ligne sur un hash volé) un mot de passe, il ne
 * peut pas se connecter sans le code à 6 chiffres généré sur le téléphone de
 * l'utilisateur. C'est la défense la plus efficace contre le vol d'identifiants.
 *
 * Codes de secours : 8 codes à usage unique, affichés une fois, stockés hachés,
 * pour ne jamais se verrouiller dehors si le téléphone est perdu.
 *
 * @package KeysO_WAF
 */

namespace KeysO_WAF;

if (!defined('ABSPATH')) exit;

final class TwoFactor
{
    private const META_SECRET   = 'keyso_2fa_secret';
    private const META_ENABLED  = 'keyso_2fa_enabled';
    private const META_RECOVERY = 'keyso_2fa_recovery';

    public function boot(): void
    {
        // Enrôlement dans le profil utilisateur
        add_action('show_user_profile', [$this, 'profileFields']);
        add_action('edit_user_profile', [$this, 'profileFields']);
        add_action('personal_options_update', [$this, 'saveProfile']);
        add_action('edit_user_profile_update', [$this, 'saveProfile']);

        // Application au login
        add_filter('authenticate', [$this, 'enforce'], 31, 1);
        add_action('login_form', [$this, 'loginField']);
    }

    // ══════════════════════════════════════════════════════════
    // Cœur TOTP (RFC 6238 / 4648) — pur PHP, sans dépendance
    // ══════════════════════════════════════════════════════════
    private const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    public static function base32Encode(string $data): string
    {
        $out = ''; $buffer = 0; $bits = 0;
        $len = strlen($data);
        for ($i = 0; $i < $len; $i++) {
            $buffer = ($buffer << 8) | ord($data[$i]);
            $bits += 8;
            while ($bits >= 5) {
                $bits -= 5;
                $out .= self::B32[($buffer >> $bits) & 0x1F];
            }
        }
        if ($bits > 0) {
            $out .= self::B32[($buffer << (5 - $bits)) & 0x1F];
        }
        return $out;
    }

    public static function base32Decode(string $b32): string
    {
        $b32 = strtoupper($b32);
        $out = ''; $buffer = 0; $bits = 0;
        $len = strlen($b32);
        for ($i = 0; $i < $len; $i++) {
            $val = strpos(self::B32, $b32[$i]);
            if ($val === false) continue;
            $buffer = ($buffer << 5) | $val;
            $bits += 5;
            if ($bits >= 8) {
                $bits -= 8;
                $out .= chr(($buffer >> $bits) & 0xFF);
            }
        }
        return $out;
    }

    public static function code(string $secret, ?int $time = null, int $digits = 6, int $step = 30): string
    {
        $key = self::base32Decode($secret);
        $counter = intdiv($time ?? time(), $step);
        $bin = pack('N*', 0, $counter);              // compteur 64-bit big-endian
        $hash = hash_hmac('sha1', $bin, $key, true);
        $offset = ord($hash[strlen($hash) - 1]) & 0x0F;
        $part = ((ord($hash[$offset]) & 0x7F) << 24)
              | ((ord($hash[$offset + 1]) & 0xFF) << 16)
              | ((ord($hash[$offset + 2]) & 0xFF) << 8)
              |  (ord($hash[$offset + 3]) & 0xFF);
        return str_pad((string) ($part % (10 ** $digits)), $digits, '0', STR_PAD_LEFT);
    }

    /** Vérifie un code avec tolérance ±1 fenêtre (dérive d'horloge). */
    public static function verify(string $secret, string $input, int $window = 1): bool
    {
        $input = preg_replace('/\D+/', '', $input);
        if ($input === '' || $secret === '') return false;
        $t = time();
        for ($i = -$window; $i <= $window; $i++) {
            if (hash_equals(self::code($secret, $t + $i * 30), $input)) {
                return true;
            }
        }
        return false;
    }

    private static function newSecret(): string
    {
        return self::base32Encode(random_bytes(20)); // 160 bits
    }

    // ══════════════════════════════════════════════════════════
    // Enrôlement (profil utilisateur)
    // ══════════════════════════════════════════════════════════
    public function profileFields($user): void
    {
        $enabled = (bool) get_user_meta($user->ID, self::META_ENABLED, true);
        $secret  = (string) get_user_meta($user->ID, self::META_SECRET, true);

        // Génère un secret en attente si l'utilisateur n'en a pas encore
        if ($secret === '') {
            $secret = self::newSecret();
            update_user_meta($user->ID, self::META_SECRET, $secret);
        }

        $site   = wp_parse_url(home_url('/'), PHP_URL_HOST) ?: 'WordPress';
        $label  = rawurlencode($site . ':' . $user->user_login);
        $issuer = rawurlencode($site);
        $otpauth = "otpauth://totp/{$label}?secret={$secret}&issuer={$issuer}&digits=6&period=30";
        ?>
        <h2 id="keyso-2fa">🔐 <?php esc_html_e('Double authentification (KeysO-WAF)', 'keyso-waf'); ?></h2>
        <table class="form-table" role="presentation">
            <tr>
                <th><?php esc_html_e('Statut', 'keyso-waf'); ?></th>
                <td>
                    <strong style="color:<?php echo $enabled ? '#008751' : '#E8112D'; ?>">
                        <?php echo esc_html($enabled ? __('ACTIVÉE', 'keyso-waf') : __('Désactivée', 'keyso-waf')); ?>
                    </strong>
                </td>
            </tr>
            <?php if (!$enabled): ?>
            <tr>
                <th><?php esc_html_e('1. Clé secrète', 'keyso-waf'); ?></th>
                <td>
                    <code style="font-size:15px;letter-spacing:1px;background:#f6f7f7;padding:6px 10px;border-radius:6px"><?php echo esc_html(chunk_split($secret, 4, ' ')); ?></code>
                    <p class="description"><?php esc_html_e('Ouvrez Google Authenticator / Authy → « Ajouter un compte » → « Saisir une clé de configuration » et collez cette clé.', 'keyso-waf'); ?></p>
                    <p class="description"><?php esc_html_e('URI (pour QR) :', 'keyso-waf'); ?> <code style="font-size:11px"><?php echo esc_html($otpauth); ?></code></p>
                </td>
            </tr>
            <tr>
                <th><label for="keyso_2fa_confirm"><?php esc_html_e('2. Code de confirmation', 'keyso-waf'); ?></label></th>
                <td>
                    <input type="text" inputmode="numeric" autocomplete="one-time-code" id="keyso_2fa_confirm" name="keyso_2fa_confirm" maxlength="6" class="regular-text" placeholder="123456" />
                    <input type="hidden" name="keyso_2fa_action" value="enable" />
                    <p class="description"><?php esc_html_e('Saisissez le code à 6 chiffres affiché par l\'application, puis enregistrez le profil pour activer la 2FA.', 'keyso-waf'); ?></p>
                </td>
            </tr>
            <?php else: ?>
            <tr>
                <th><?php esc_html_e('Désactiver', 'keyso-waf'); ?></th>
                <td>
                    <label><input type="checkbox" name="keyso_2fa_action" value="disable" /> <?php esc_html_e('Désactiver la double authentification pour ce compte', 'keyso-waf'); ?></label>
                </td>
            </tr>
            <?php endif; ?>
        </table>
        <?php
    }

    public function saveProfile($user_id): void
    {
        if (!current_user_can('edit_user', $user_id)) {
            return;
        }
        $action = isset($_POST['keyso_2fa_action']) ? sanitize_key(wp_unslash($_POST['keyso_2fa_action'])) : '';

        if ($action === 'enable') {
            $secret  = (string) get_user_meta($user_id, self::META_SECRET, true);
            $confirm = isset($_POST['keyso_2fa_confirm']) ? sanitize_text_field(wp_unslash($_POST['keyso_2fa_confirm'])) : '';
            if ($secret !== '' && self::verify($secret, $confirm)) {
                update_user_meta($user_id, self::META_ENABLED, 1);
                $codes = $this->generateRecoveryCodes($user_id);
                // Affiche les codes de secours une seule fois (transient court)
                set_transient('keyso_2fa_codes_' . $user_id, $codes, 300);
                add_action('user_profile_update_errors', static function ($errors) use ($codes) {
                    $errors->add('keyso_2fa_codes', '✅ 2FA activée. CODES DE SECOURS (à conserver, usage unique) : ' . implode('  ', $codes), 'message');
                });
            } else {
                add_action('user_profile_update_errors', static function ($errors) {
                    $errors->add('keyso_2fa_bad', __('Code 2FA incorrect — la double authentification n\'a pas été activée.', 'keyso-waf'));
                });
            }
        } elseif ($action === 'disable') {
            delete_user_meta($user_id, self::META_ENABLED);
            delete_user_meta($user_id, self::META_SECRET);
            delete_user_meta($user_id, self::META_RECOVERY);
        }
    }

    /** @return string[] Codes en clair (affichés une fois) ; les hachés sont stockés. */
    private function generateRecoveryCodes(int $user_id): array
    {
        $plain = []; $hashed = [];
        for ($i = 0; $i < 8; $i++) {
            $c = strtoupper(bin2hex(random_bytes(4))); // 8 hex
            $c = substr($c, 0, 4) . '-' . substr($c, 4, 4);
            $plain[] = $c;
            $hashed[] = hash('sha256', $c);
        }
        update_user_meta($user_id, self::META_RECOVERY, $hashed);
        return $plain;
    }

    // ══════════════════════════════════════════════════════════
    // Application au login
    // ══════════════════════════════════════════════════════════
    public function loginField(): void
    {
        ?>
        <p>
            <label for="keyso_2fa_code"><?php esc_html_e('Code 2FA (si activé)', 'keyso-waf'); ?><br />
            <input type="text" inputmode="numeric" autocomplete="one-time-code" name="keyso_2fa_code" id="keyso_2fa_code" class="input" value="" size="20" /></label>
        </p>
        <?php
    }

    /**
     * @param mixed $user
     * @return mixed
     */
    public function enforce($user)
    {
        // N'agit que si le mot de passe a déjà été validé (objet utilisateur réel)
        if (!($user instanceof \WP_User)) {
            return $user;
        }
        if (!get_user_meta($user->ID, self::META_ENABLED, true)) {
            return $user;
        }
        // Contexte sans formulaire (ex. cookie déjà valide) : on laisse passer
        if (!isset($_POST['log']) && !isset($_POST['pwd'])) {
            return $user;
        }

        $code = isset($_POST['keyso_2fa_code']) ? sanitize_text_field(wp_unslash($_POST['keyso_2fa_code'])) : '';
        if ($code === '') {
            return new \WP_Error('keyso_2fa_required', __('Code de double authentification requis.', 'keyso-waf'));
        }

        $secret = (string) get_user_meta($user->ID, self::META_SECRET, true);
        if ($secret !== '' && self::verify($secret, $code)) {
            return $user;
        }
        if ($this->consumeRecoveryCode($user->ID, $code)) {
            return $user;
        }

        Logger::log([
            'ip'         => Guard::staticClientIp(),
            'method'     => $_SERVER['REQUEST_METHOD'] ?? '',
            'path'       => 'wp-login.php [2fa]',
            'threat'     => 'brute_force',
            'detail'     => "Code 2FA invalide pour {$user->user_login}",
            'action'     => 'block',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
        ]);
        return new \WP_Error('keyso_2fa_invalid', __('Code de double authentification invalide.', 'keyso-waf'));
    }

    private function consumeRecoveryCode(int $user_id, string $code): bool
    {
        $code = strtoupper(trim($code));
        $stored = get_user_meta($user_id, self::META_RECOVERY, true);
        if (!is_array($stored) || $stored === []) {
            return false;
        }
        $hash = hash('sha256', $code);
        $idx = array_search($hash, $stored, true);
        if ($idx === false) {
            return false;
        }
        unset($stored[$idx]);                                // usage unique
        update_user_meta($user_id, self::META_RECOVERY, array_values($stored));
        return true;
    }

    /** True si l'utilisateur a la 2FA active (utilitaire). */
    public static function isEnabledFor(int $user_id): bool
    {
        return (bool) get_user_meta($user_id, self::META_ENABLED, true);
    }
}
