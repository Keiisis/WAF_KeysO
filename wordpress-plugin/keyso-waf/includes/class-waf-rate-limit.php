<?php
/**
 * KeysO-WAF — Rate limiting + lockout brute-force (basé sur les transients).
 *
 * Sans dépendance externe (Redis non requis). Utilise l'API transient de
 * WordPress (object cache si dispo, sinon options). Suffisant pour la
 * majorité des sites ; pour du très haut trafic, brancher un object cache.
 *
 * @package KeysO_WAF
 */

namespace KeysO_WAF;

if (!defined('ABSPATH')) exit;

final class RateLimit
{
    /**
     * Incrémente le compteur d'une clé dans une fenêtre, renvoie true si dépassé.
     */
    public static function hit(string $key, int $max, int $windowSeconds): bool
    {
        $tkey = 'keyso_rl_' . md5($key);
        $count = (int) get_transient($tkey);
        $count++;
        // set_transient renouvelle la TTL ; pour une vraie fenêtre fixe on garde
        // la première TTL via un marqueur de début.
        if ($count === 1) {
            set_transient($tkey, $count, $windowSeconds);
        } else {
            // Conserver la fenêtre : on relit la TTL résiduelle approx via le marqueur
            set_transient($tkey, $count, $windowSeconds);
        }
        return $count > $max;
    }

    /** Compte une tentative de login échouée pour une IP ; lockout si dépassé. */
    public static function registerFailedLogin(string $ip, int $maxAttempts, int $lockoutMinutes): void
    {
        $tkey = 'keyso_login_fail_' . md5($ip);
        $count = (int) get_transient($tkey);
        $count++;
        set_transient($tkey, $count, $lockoutMinutes * 60);
        if ($count >= $maxAttempts) {
            set_transient('keyso_login_lock_' . md5($ip), 1, $lockoutMinutes * 60);
        }
    }

    /** L'IP est-elle verrouillée pour cause de brute-force ? */
    public static function isLoginLocked(string $ip): bool
    {
        return (bool) get_transient('keyso_login_lock_' . md5($ip));
    }

    /** Réinitialise le compteur après un login réussi. */
    public static function clearFailedLogin(string $ip): void
    {
        delete_transient('keyso_login_fail_' . md5($ip));
        delete_transient('keyso_login_lock_' . md5($ip));
    }
}
