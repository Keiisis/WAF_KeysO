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

        // Cache objet persistant (Redis/Memcached) → incrément ATOMIQUE :
        // évite la condition de course du couple get/set sous forte charge.
        if (wp_using_ext_object_cache()) {
            $group = 'keyso_waf_rl';
            $count = wp_cache_get($tkey, $group);
            if ($count === false) {
                wp_cache_add($tkey, 1, $group, $windowSeconds);
                $count = 1;
            } else {
                $count = wp_cache_incr($tkey, 1, $group);
                if ($count === false) { // clé expirée entre get et incr
                    wp_cache_add($tkey, 1, $group, $windowSeconds);
                    $count = 1;
                }
            }
            return (int) $count > $max;
        }

        // Repli : transients (fenêtre glissante — la TTL est renouvelée tant que
        // le trafic continue, ce qui est plus strict, donc sûr pour un WAF).
        $count = (int) get_transient($tkey) + 1;
        set_transient($tkey, $count, $windowSeconds);
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
