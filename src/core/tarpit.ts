// ══════════════════════════════════════════════════════════════
// 🐢  KeysO-WAF · core/tarpit — Tarpit BORNÉ (anti auto-DoS)
// ══════════════════════════════════════════════════════════════
//
// Problème : ralentir un attaquant avec `await sleep(N)` occupe la
// fonction serverless (facturée + concurrence bloquée). Un flood de
// requêtes tarpitées peut ÉPUISER ta concurrence ⇒ auto-DoS.
//
// Solution : un sémaphore global qui plafonne le nombre de tarpits
// SIMULTANÉS. Au-delà du plafond, on renonce au délai (la requête est
// quand même traitée/bloquée par ailleurs) — on ne s'auto-sabote pas.
//
// En serverless, l'état est par-instance : c'est exactement ce qui
// protège la concurrence DE CETTE instance.
//
// PORTABLE — zéro dépendance.
// ══════════════════════════════════════════════════════════════

export interface TarpitOptions {
    /** Délai max autorisé (ms). Défaut 8000. */
    maxDelayMs?: number
    /** Nombre de tarpits simultanés autorisés. Défaut 50. */
    maxConcurrent?: number
}

export interface TarpitResult {
    /** true si le délai a réellement été appliqué. */
    applied: boolean
    /** Délai effectivement attendu (ms). */
    delayMs: number
    /** Raison si non appliqué. */
    skippedReason?: 'cap_reached' | 'zero_delay'
}

let activeTarpits = 0
let totalApplied = 0
let totalSkipped = 0

const sleep = (ms: number) => new Promise<void>(r => setTimeout(r, ms))

/**
 * Applique un tarpit borné. Ne dépasse JAMAIS le plafond de concurrence.
 */
export async function boundedTarpit(delayMs: number, options: TarpitOptions = {}): Promise<TarpitResult> {
    const maxDelay = options.maxDelayMs ?? 8000
    const maxConcurrent = options.maxConcurrent ?? 50
    const delay = Math.max(0, Math.min(maxDelay, Math.floor(delayMs)))

    if (delay === 0) {
        return { applied: false, delayMs: 0, skippedReason: 'zero_delay' }
    }

    // Plafond atteint → on renonce au délai pour ne pas saturer la concurrence
    if (activeTarpits >= maxConcurrent) {
        totalSkipped++
        return { applied: false, delayMs: 0, skippedReason: 'cap_reached' }
    }

    activeTarpits++
    try {
        await sleep(delay)
        totalApplied++
        return { applied: true, delayMs: delay }
    } finally {
        activeTarpits--
    }
}

/** Délai gradué selon un score de confiance (0–100) — plus bas = plus lent. */
export function tarpitDelayForTrust(trustScore: number): number {
    const s = Math.max(0, Math.min(100, trustScore))
    if (s >= 70) return 0
    if (s >= 50) return 800
    if (s >= 30) return 2000
    if (s >= 10) return 4000
    return 6000
}

/** Métriques d'observabilité (par instance). */
export function tarpitMetrics(): { active: number; totalApplied: number; totalSkipped: number } {
    return { active: activeTarpits, totalApplied, totalSkipped }
}

/** Réinitialise les compteurs (tests). */
export function __resetTarpitMetrics(): void {
    activeTarpits = 0; totalApplied = 0; totalSkipped = 0
}
