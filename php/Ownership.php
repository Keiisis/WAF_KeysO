<?php
/**
 * ══════════════════════════════════════════════════════════════
 *  WafCore\Ownership — Autorisation au niveau objet (port PHP)
 * ══════════════════════════════════════════════════════════════
 *
 * Port fidèle de core/ownership.ts. PORTABLE : le resolver de propriété
 * est injecté (callable) → le core ne connaît pas la base de données.
 *
 * Anti-IDOR/BOLA RÉEL : vérifie qu'un utilisateur a le droit de toucher
 * UNE ressource précise (pas seulement la détection d'énumération).
 *
 * Usage WordPress (resolver wpdb) :
 *   $resolver = function(array $q): array {
 *       global $wpdb;
 *       $owner = $wpdb->get_var($wpdb->prepare(
 *           "SELECT post_author FROM {$wpdb->posts} WHERE ID = %d", $q['resourceId']
 *       ));
 *       return ['ownerId' => $owner, 'notFound' => $owner === null];
 *   };
 *   $verdict = \WafCore\Ownership::verify($resolver, [
 *       'userId' => get_current_user_id(),
 *       'resourceType' => 'post',
 *       'resourceId' => $post_id,
 *   ]);
 *   if (!$verdict['allowed']) { wp_send_json_error('Accès refusé', 403); }
 * ══════════════════════════════════════════════════════════════
 */

namespace WafCore;

final class Ownership
{
    /**
     * Vérifie qu'un utilisateur possède (ou a accès à) une ressource.
     * Ne lève jamais — fail-closed sur erreur resolver.
     *
     * @param callable $resolver fn(array $query): array{ownerId:?string,notFound:bool}
     * @param array{userId:string,resourceType:string,resourceId:string} $query
     * @param array{missingPolicy?:string,isStaff?:callable} $options
     *        missingPolicy: 'deny' (défaut) | 'allow'
     *        isStaff: fn(string $userId): bool
     * @return array{allowed:bool,decision:string,actualOwnerId:?string,detail:string}
     */
    public static function verify(callable $resolver, array $query, array $options = []): array
    {
        $missingPolicy = $options['missingPolicy'] ?? 'deny';

        // 1. Override staff
        if (isset($options['isStaff']) && is_callable($options['isStaff'])) {
            try {
                if (($options['isStaff'])($query['userId']) === true) {
                    return self::v(true, 'staff_override', null, "Accès staff transverse autorisé");
                }
            } catch (\Throwable $e) { /* continue */ }
        }

        // 2. Résoudre le propriétaire
        try {
            $resolution = $resolver($query);
        } catch (\Throwable $e) {
            // fail-closed : on refuse plutôt que de fuir
            return self::v(false, 'not_found_denied', null,
                "Erreur resolver ownership (" . $e->getMessage() . ") — accès refusé par sécurité");
        }

        $ownerId  = $resolution['ownerId']  ?? null;
        $notFound = $resolution['notFound'] ?? ($ownerId === null);

        // 3. Ressource introuvable
        if ($notFound || $ownerId === null) {
            if ($missingPolicy === 'allow') {
                return self::v(true, 'not_found_allowed', null,
                    "Ressource {$query['resourceType']}#{$query['resourceId']} introuvable — policy 'allow'");
            }
            return self::v(false, 'not_found_denied', null,
                "Ressource {$query['resourceType']}#{$query['resourceId']} introuvable — policy 'deny'");
        }

        // 4. Propriétaire confirmé
        if ((string)$ownerId === (string)$query['userId']) {
            return self::v(true, 'owner', (string)$ownerId, "Propriétaire confirmé");
        }

        // 5. IDOR/BOLA — ressource d'autrui
        return self::v(false, 'foreign', (string)$ownerId,
            "IDOR/BOLA : user {$query['userId']} demande {$query['resourceType']}#{$query['resourceId']} appartenant à {$ownerId}");
    }

    /** @return array{allowed:bool,decision:string,actualOwnerId:?string,detail:string} */
    private static function v(bool $allowed, string $decision, ?string $owner, string $detail): array
    {
        return ['allowed' => $allowed, 'decision' => $decision, 'actualOwnerId' => $owner, 'detail' => $detail];
    }
}
