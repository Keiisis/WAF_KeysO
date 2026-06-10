// ══════════════════════════════════════════════════════════════
// 🔐  @waf-core/ownership — Autorisation au niveau objet (anti-IDOR/BOLA)
// ══════════════════════════════════════════════════════════════
//
// PORTABLE — Zéro dépendance datastore. Le cœur ne sait PAS comment
// on stocke les ressources : il reçoit un "resolver" injecté qui
// répond à une seule question : « qui possède cette ressource ? ».
//
// C'est LE point qui manquait au WAF : la détection d'énumération
// (idor.ts) repère un balayage, mais ne vérifie pas qu'un utilisateur
// a le DROIT de toucher UNE ressource précise. Ce module comble ça.
//
// Portabilité :
//   - Next.js + Supabase → adapter `supabase-ownership.ts`
//   - WordPress / PHP     → resolver basé sur wpdb / PDO (à écrire)
//   - Express + Prisma    → resolver basé sur Prisma (à écrire)
// Le core ci-dessous ne change JAMAIS d'une plateforme à l'autre.
//
// Usage (bas niveau, framework-agnostic) :
//   const resolver: OwnershipResolver = async ({ resourceType, resourceId }) => ...
//   const verdict = await verifyOwnership(resolver, {
//     userId, resourceType: 'invoice', resourceId: '42',
//   })
//   if (!verdict.allowed) { /* 403 / deception */ }
// ══════════════════════════════════════════════════════════════

export interface OwnershipQuery {
    /** L'utilisateur qui fait la demande. */
    userId: string
    /** Type logique de ressource ('invoice', 'dossier', 'document'…). */
    resourceType: string
    /** Identifiant de la ressource demandée. */
    resourceId: string
}

/**
 * Stratégie quand la ressource est INTROUVABLE dans le datastore.
 *  - 'deny'  (défaut, recommandé) : refuse → fail-closed, pas de fuite
 *  - 'allow' : laisse passer → fail-open (à n'utiliser que si une autre
 *              couche, ex. 404 naturel de la route, gère le cas)
 */
export type MissingResourcePolicy = 'deny' | 'allow'

export interface OwnershipResolution {
    /** owner_id de la ressource, ou null si introuvable. */
    ownerId: string | null
    /** true si la ressource n'existe pas du tout dans le datastore. */
    notFound: boolean
}

/**
 * Resolver injecté : interroge le datastore et renvoie le propriétaire.
 * C'est la SEULE pièce qui change selon la plateforme.
 */
export type OwnershipResolver = (query: OwnershipQuery) => Promise<OwnershipResolution>

export type OwnershipDecision =
    | 'owner'                  // l'utilisateur possède la ressource
    | 'staff_override'         // un staff/admin a un accès légitime global
    | 'foreign'                // ressource appartient à quelqu'un d'autre → IDOR
    | 'not_found_denied'       // ressource absente + policy 'deny'
    | 'not_found_allowed'      // ressource absente + policy 'allow'

export interface OwnershipVerdict {
    allowed: boolean
    decision: OwnershipDecision
    /** Renseigné uniquement si la ressource a un propriétaire identifié. */
    actualOwnerId: string | null
    detail: string
}

export interface VerifyOwnershipOptions {
    /** Politique quand la ressource est introuvable. Défaut : 'deny'. */
    missingPolicy?: MissingResourcePolicy
    /**
     * Override staff : fonction qui dit si l'utilisateur a un accès
     * transverse légitime (admin/agent/CEO). Optionnel.
     */
    isStaff?: (userId: string) => Promise<boolean> | boolean
}

/**
 * Vérifie qu'un utilisateur a le droit de toucher une ressource précise.
 * Pur : aucune I/O directe — toute I/O passe par le resolver injecté.
 * Ne lève jamais : en cas d'erreur resolver, retourne un refus explicite.
 */
export async function verifyOwnership(
    resolver: OwnershipResolver,
    query: OwnershipQuery,
    options: VerifyOwnershipOptions = {}
): Promise<OwnershipVerdict> {
    const missingPolicy: MissingResourcePolicy = options.missingPolicy ?? 'deny'

    // 1. Override staff (avant même de toucher le datastore ressource)
    if (options.isStaff) {
        try {
            const staff = await options.isStaff(query.userId)
            if (staff) {
                return {
                    allowed: true, decision: 'staff_override',
                    actualOwnerId: null,
                    detail: `Accès staff transverse autorisé (user ${query.userId})`,
                }
            }
        } catch {
            // si la vérif staff échoue, on continue avec la vérif propriétaire
        }
    }

    // 2. Résoudre le propriétaire réel
    let resolution: OwnershipResolution
    try {
        resolution = await resolver(query)
    } catch (e) {
        // fail-closed sur erreur resolver : on refuse plutôt que de fuir
        return {
            allowed: false, decision: 'not_found_denied', actualOwnerId: null,
            detail: `Erreur resolver ownership (${e instanceof Error ? e.message : 'inconnue'}) — accès refusé par sécurité`,
        }
    }

    // 3. Ressource introuvable
    if (resolution.notFound || resolution.ownerId === null) {
        if (missingPolicy === 'allow') {
            return {
                allowed: true, decision: 'not_found_allowed', actualOwnerId: null,
                detail: `Ressource ${query.resourceType}#${query.resourceId} introuvable — policy 'allow'`,
            }
        }
        return {
            allowed: false, decision: 'not_found_denied', actualOwnerId: null,
            detail: `Ressource ${query.resourceType}#${query.resourceId} introuvable — policy 'deny'`,
        }
    }

    // 4. Comparaison propriétaire
    if (resolution.ownerId === query.userId) {
        return {
            allowed: true, decision: 'owner', actualOwnerId: resolution.ownerId,
            detail: `Propriétaire confirmé`,
        }
    }

    // 5. IDOR/BOLA — l'utilisateur demande la ressource d'autrui
    return {
        allowed: false, decision: 'foreign', actualOwnerId: resolution.ownerId,
        detail: `IDOR/BOLA : user ${query.userId} demande ${query.resourceType}#${query.resourceId} appartenant à ${resolution.ownerId}`,
    }
}
