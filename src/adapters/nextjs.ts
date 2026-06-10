// ══════════════════════════════════════════════════════════════
// 🔌  @waf-adapters/nextjs — Helpers Next.js (App Router)
// ══════════════════════════════════════════════════════════════
//
// COUCHE JETABLE. Relie le core portable (body-scanner, ownership)
// au monde Next.js : lecture de body, NextResponse, headers Bearer.
// Pour porter ailleurs (Express, PHP), on réécrit cet adapter ;
// le core reste identique.
// ══════════════════════════════════════════════════════════════

import { NextResponse } from 'next/server'
import {
    scanBody,
    type BodyScanOptions,
    type BodyScanVerdict,
} from '../core/body-scanner'
import {
    verifyOwnership,
    type OwnershipResolver,
    type OwnershipVerdict,
    type VerifyOwnershipOptions,
} from '../core/ownership'

// ── Réponses standard ─────────────────────────────────────────
function wafReject(message: string, status: number): NextResponse {
    return NextResponse.json({ error: message }, { status })
}

// ══════════════════════════════════════════════════════════════
// #2 — Analyse de body (prototype pollution / RCE / SSRF / DoS)
// ══════════════════════════════════════════════════════════════

export interface ScanRequestBodyResult {
    /** Body parsé — à RÉUTILISER dans la route (le stream est consommé). */
    body: unknown
    verdict: BodyScanVerdict
    /** Réponse à retourner immédiatement si la requête est dangereuse, sinon null. */
    rejection: NextResponse | null
}

export interface ScanRequestBodyOptions {
    scan?: Partial<BodyScanOptions>
    /** Callback de log/alerte branché sur l'infra WAF du projet. */
    onThreat?: (verdict: BodyScanVerdict) => void
    /** Message d'erreur exposé au client (générique par défaut). */
    rejectMessage?: string
}

/**
 * Lit le corps JSON d'une requête Next.js, le scanne, et renvoie :
 *   - `body`      : le payload parsé (à réutiliser — NE PAS refaire req.json())
 *   - `verdict`   : résultat de l'analyse structurelle
 *   - `rejection` : NextResponse 400 prête si dangereux, sinon null
 *
 * Pattern d'usage dans une route :
 *   const { body, rejection } = await scanRequestBody(req)
 *   if (rejection) return rejection
 *   // ... utiliser `body` normalement
 */
export async function scanRequestBody(
    // Accepte NextRequest OU Request standard (on n'utilise que .clone().json())
    // → plus portable : marche dans toutes les routes, App Router ou non.
    req: Request,
    options: ScanRequestBodyOptions = {}
): Promise<ScanRequestBodyResult> {
    let body: unknown = undefined
    try {
        // clone() pour ne pas casser une éventuelle relecture downstream
        body = await req.clone().json()
    } catch {
        // pas de body JSON (GET, form-data, vide) → rien à scanner
        return { body: undefined, verdict: { safe: true, threat: null, confidence: 0, path: '', detail: '' }, rejection: null }
    }

    const verdict = scanBody(body, options.scan)
    if (!verdict.safe) {
        options.onThreat?.(verdict)
        return {
            body,
            verdict,
            rejection: wafReject(options.rejectMessage || 'Requête invalide.', 400),
        }
    }

    return { body, verdict, rejection: null }
}

// ══════════════════════════════════════════════════════════════
// #1 — Autorisation au niveau objet (anti-IDOR/BOLA)
// ══════════════════════════════════════════════════════════════

export interface AssertOwnershipParams {
    userId: string
    resourceType: string
    resourceId: string
    resolver: OwnershipResolver
    options?: VerifyOwnershipOptions
    /** Callback de log/alerte (IDOR détecté) branché sur l'infra WAF. */
    onViolation?: (verdict: OwnershipVerdict) => void
    /**
     * Mode de réponse en cas d'accès refusé :
     *   - 'block'   (défaut) : 403 JSON
     *   - 'deceive' : 404 (ressource "inexistante") — ne révèle pas qu'elle existe
     */
    rejectMode?: 'block' | 'deceive'
}

export interface AssertOwnershipResult {
    verdict: OwnershipVerdict
    /** NextResponse à retourner si refusé, sinon null. */
    rejection: NextResponse | null
}

/**
 * Vérifie que `userId` a le droit de toucher `resourceType#resourceId`.
 * Renvoie une `rejection` prête (403 ou 404) si l'accès est illégitime.
 *
 * Pattern d'usage dans une route :
 *   const { rejection } = await assertOwnership({
 *     userId, resourceType: 'invoice', resourceId: id, resolver,
 *   })
 *   if (rejection) return rejection
 */
export async function assertOwnership(
    params: AssertOwnershipParams
): Promise<AssertOwnershipResult> {
    const verdict = await verifyOwnership(
        params.resolver,
        {
            userId: params.userId,
            resourceType: params.resourceType,
            resourceId: params.resourceId,
        },
        params.options
    )

    if (verdict.allowed) {
        return { verdict, rejection: null }
    }

    params.onViolation?.(verdict)

    // 'deceive' : on prétend que la ressource n'existe pas (anti-énumération)
    if (params.rejectMode === 'deceive') {
        return { verdict, rejection: wafReject('Ressource introuvable.', 404) }
    }
    return { verdict, rejection: wafReject('Accès refusé.', 403) }
}
