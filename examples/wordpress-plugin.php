<?php
/**
 * Plugin Name: KeysO-WAF Guard
 * Description: Exemple de plugin WordPress utilisant KeysO-WAF (port PHP du core)
 *              pour bloquer prototype pollution / RCE / SSRF dans les requêtes
 *              REST, et appliquer l'autorisation au niveau objet (anti-IDOR).
 * Version: 0.1.0
 * Requires PHP: 8.0
 *
 * Placez php/BodyScanner.php et php/Ownership.php dans ce plugin puis :
 *   require_once __DIR__ . '/BodyScanner.php';
 *   require_once __DIR__ . '/Ownership.php';
 */

if (!defined('ABSPATH')) exit;

require_once __DIR__ . '/BodyScanner.php';
require_once __DIR__ . '/Ownership.php';

use WafCore\BodyScanner;
use WafCore\Ownership;

/**
 * #2 — Analyse structurelle de TOUTES les requêtes REST entrantes.
 * Bloque proto pollution / RCE / SSRF / DoS avant d'atteindre vos endpoints.
 */
add_filter('rest_pre_dispatch', function ($result, $server, $request) {
    $body = $request->get_json_params();
    if (is_array($body) && !empty($body)) {
        $verdict = BodyScanner::scan($body);
        if (!$verdict['safe']) {
            error_log("[KeysO-WAF] {$verdict['threat']} @ {$verdict['path']} — {$verdict['detail']}");
            return new WP_Error('waf_blocked', 'Requête invalide.', ['status' => 400]);
        }
    }
    return $result;
}, 10, 3);

/**
 * #1 — Exemple d'autorisation au niveau objet sur un endpoint custom.
 * Empêche un utilisateur de lire la commande WooCommerce d'un autre (IDOR).
 */
add_action('rest_api_init', function () {
    register_rest_route('keyso/v1', '/order/(?P<id>\d+)', [
        'methods'  => 'GET',
        'permission_callback' => '__return_true',
        'callback' => function (WP_REST_Request $req) {
            // Resolver : qui possède cette commande WooCommerce ?
            $resolver = function (array $q): array {
                global $wpdb;
                $owner = $wpdb->get_var($wpdb->prepare(
                    "SELECT meta_value FROM {$wpdb->postmeta}
                     WHERE post_id = %d AND meta_key = '_customer_user'",
                    (int) $q['resourceId']
                ));
                return ['ownerId' => $owner !== null ? (string) $owner : null, 'notFound' => $owner === null];
            };

            $verdict = Ownership::verify($resolver, [
                'userId'       => (string) get_current_user_id(),
                'resourceType' => 'order',
                'resourceId'   => (string) $req['id'],
            ], [
                // Un admin (manage_woocommerce) a un accès transverse légitime
                'isStaff' => fn(string $uid) => user_can((int) $uid, 'manage_woocommerce'),
            ]);

            if (!$verdict['allowed']) {
                return new WP_Error('forbidden', 'Ressource introuvable.', ['status' => 404]);
            }
            return ['ok' => true, 'order' => $req['id']];
        },
    ]);
});
