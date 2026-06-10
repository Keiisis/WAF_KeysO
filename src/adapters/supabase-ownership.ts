// ══════════════════════════════════════════════════════════════
// 🔌  KeysO-WAF · adapters/supabase-ownership — Resolver Supabase/Postgres
// ══════════════════════════════════════════════════════════════
//
// COUCHE JETABLE/REMPLAÇABLE. Seul fichier qui connaît Supabase.
// Pour porter ailleurs : écrire un resolver wpdb (WordPress), PDO (PHP),
// Prisma (Node)… Le core (core/ownership.ts) ne change jamais.
//
// On interroge les VRAIES tables (pas une copie "shadow" qui dériverait).
// ══════════════════════════════════════════════════════════════

import type { SupabaseClient } from '@supabase/supabase-js'
import type { OwnershipResolver, OwnershipResolution } from '../core/ownership'

export interface ResourceMapEntry {
    /** Table réelle. */
    table: string
    /** Colonne identifiant (défaut: 'id'). */
    idColumn?: string
    /** Colonne portant l'owner (ex: 'user_id', 'client_id'). */
    ownerColumn: string
    /** Résolution d'owner indirecte (jointure parente). */
    indirect?: (supabase: SupabaseClient, resourceId: string) => Promise<string | null>
}

export type ResourceMap = Record<string, ResourceMapEntry>

/**
 * Exemple de carte de ressources — À ADAPTER à votre schéma.
 * (Chaque app déclare quelles tables/colonnes portent la propriété.)
 */
export const EXAMPLE_RESOURCE_MAP: ResourceMap = {
    invoice: { table: 'invoices', ownerColumn: 'user_id' },
    order:   { table: 'orders',   ownerColumn: 'user_id' },
    profile: { table: 'profiles', ownerColumn: 'id' },
}

/**
 * Crée un resolver d'ownership Supabase à partir d'une carte de ressources.
 * Le client doit être en SERVICE ROLE (bypass RLS) : c'est le WAF qui vérifie.
 */
export function createSupabaseOwnershipResolver(
    supabase: SupabaseClient,
    resourceMap: ResourceMap
): OwnershipResolver {
    return async ({ resourceType, resourceId }): Promise<OwnershipResolution> => {
        const entry = resourceMap[resourceType]
        if (!entry) return { ownerId: null, notFound: true }

        if (entry.indirect) {
            const ownerId = await entry.indirect(supabase, resourceId)
            return { ownerId, notFound: ownerId === null }
        }

        const idCol = entry.idColumn || 'id'
        const { data, error } = await supabase
            .from(entry.table)
            .select(entry.ownerColumn)
            .eq(idCol, resourceId)
            .maybeSingle()

        if (error || !data) return { ownerId: null, notFound: true }

        const ownerId = (data as unknown as Record<string, unknown>)[entry.ownerColumn]
        return {
            ownerId: typeof ownerId === 'string' ? ownerId : null,
            notFound: ownerId == null,
        }
    }
}
