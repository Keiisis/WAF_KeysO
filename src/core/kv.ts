// ══════════════════════════════════════════════════════════════
// 🗄️  KeysO-WAF · core/kv — Abstraction store partagé (Redis-like)
// ══════════════════════════════════════════════════════════════
//
// Corrige le morcellement de la RAM en serverless : sur Vercel, chaque
// instance a sa propre mémoire → un attaquant réparti sur N instances
// échappe au comptage local. Solution : un store PARTAGÉ (Upstash Redis,
// Cloudflare KV…) injecté via cette interface.
//
// Le core ne connaît AUCUN provider : il manipule une interface `KvStore`.
// On fournit un `MemoryKv` (fallback 3ᵉ niveau) et un adapter Upstash REST
// (adapters/upstash.ts). Tout provider peut être branché.
//
// PORTABLE — zéro dépendance.
// ══════════════════════════════════════════════════════════════

export interface KvStore {
    /** Incrémente une clé ; pose une expiration au 1er incrément. Renvoie la valeur. */
    incr(key: string, ttlSeconds: number): Promise<number>
    /** Lit une valeur numérique (0 si absente). */
    get(key: string): Promise<number | null>
    /** Pose une valeur avec TTL. */
    set(key: string, value: number, ttlSeconds: number): Promise<void>
    /** Supprime une clé. */
    del(key: string): Promise<void>
}

// ── Implémentation mémoire (fallback / dev / tests) ───────────────
interface MemEntry { value: number; expiresAt: number }

export class MemoryKv implements KvStore {
    private store = new Map<string, MemEntry>()
    private readonly maxEntries: number

    constructor(maxEntries = 50_000) {
        this.maxEntries = maxEntries
    }

    private now(): number { return Date.now() }

    private evictExpired(): void {
        const now = this.now()
        for (const [k, e] of this.store) {
            if (e.expiresAt <= now) this.store.delete(k)
        }
        // Cap dur : éviction LRU grossière (les plus proches de l'expiration)
        if (this.store.size > this.maxEntries) {
            const sorted = [...this.store.entries()].sort((a, b) => a[1].expiresAt - b[1].expiresAt)
            const drop = this.store.size - this.maxEntries
            for (let i = 0; i < drop; i++) this.store.delete(sorted[i][0])
        }
    }

    async incr(key: string, ttlSeconds: number): Promise<number> {
        const now = this.now()
        const e = this.store.get(key)
        if (!e || e.expiresAt <= now) {
            this.store.set(key, { value: 1, expiresAt: now + ttlSeconds * 1000 })
            this.evictExpired()
            return 1
        }
        e.value++
        return e.value
    }

    async get(key: string): Promise<number | null> {
        const e = this.store.get(key)
        if (!e || e.expiresAt <= this.now()) { this.store.delete(key); return null }
        return e.value
    }

    async set(key: string, value: number, ttlSeconds: number): Promise<void> {
        this.store.set(key, { value, expiresAt: this.now() + ttlSeconds * 1000 })
        this.evictExpired()
    }

    async del(key: string): Promise<void> {
        this.store.delete(key)
    }
}

// ── Rate-limiter distribué (fenêtre fixe) bâti sur KvStore ────────
export interface RateLimitResult {
    allowed: boolean
    count: number
    remaining: number
    resetSeconds: number
}

/**
 * Limiteur de débit à fenêtre fixe, partagé entre instances via KvStore.
 * @param kv      store partagé (Upstash en prod, MemoryKv en fallback)
 * @param key     identité (ex: `rl:${ip}:${route}`)
 * @param max     requêtes autorisées dans la fenêtre
 * @param windowSeconds taille de la fenêtre
 */
export async function rateLimit(
    kv: KvStore,
    key: string,
    max: number,
    windowSeconds: number,
): Promise<RateLimitResult> {
    const count = await kv.incr(`rl:${key}`, windowSeconds)
    return {
        allowed: count <= max,
        count,
        remaining: Math.max(0, max - count),
        resetSeconds: windowSeconds,
    }
}

// ── Block-store distribué (bans cross-instance) ──────────────────
/**
 * Bloque une identité (IP/fingerprint) pour une durée, visible de TOUTES
 * les instances. Corrige le ban qui ne survivait pas au cold start.
 */
export async function blockIdentity(kv: KvStore, id: string, ttlSeconds: number): Promise<void> {
    await kv.set(`block:${id}`, 1, ttlSeconds)
}

export async function isBlocked(kv: KvStore, id: string): Promise<boolean> {
    return (await kv.get(`block:${id}`)) !== null
}

/**
 * Enregistre une violation distribuée ; bloque au-delà du seuil.
 * Renvoie true si l'identité vient d'être (ou est déjà) bloquée.
 */
export async function recordViolation(
    kv: KvStore,
    id: string,
    opts: { windowSeconds?: number; threshold?: number; blockTtlSeconds?: number } = {},
): Promise<{ blocked: boolean; count: number }> {
    const windowSeconds = opts.windowSeconds ?? 600
    const threshold = opts.threshold ?? 5
    const blockTtl = opts.blockTtlSeconds ?? 1800
    const count = await kv.incr(`viol:${id}`, windowSeconds)
    if (count >= threshold) {
        await blockIdentity(kv, id, blockTtl)
        return { blocked: true, count }
    }
    return { blocked: false, count }
}
