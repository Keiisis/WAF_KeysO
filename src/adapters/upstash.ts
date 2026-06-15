// ══════════════════════════════════════════════════════════════
// 🔌  KeysO-WAF · adapters/upstash — KvStore sur Upstash Redis (REST)
// ══════════════════════════════════════════════════════════════
//
// Implémente l'interface KvStore via l'API REST d'Upstash Redis —
// idéale pour Vercel Edge (HTTP, pas de connexion TCP persistante).
//
// Aucune dépendance npm : on utilise fetch() + le endpoint REST.
// Branchement :
//   const kv = createUpstashKv({
//     url: process.env.UPSTASH_REDIS_REST_URL!,
//     token: process.env.UPSTASH_REDIS_REST_TOKEN!,
//   })
//
// Si url/token absents → renvoie null (l'appelant retombe sur MemoryKv).
// ══════════════════════════════════════════════════════════════

import type { KvStore } from '../core/kv'

export interface UpstashOptions {
    url: string
    token: string
    /** Timeout par commande (ms). Défaut 1500 — on ne bloque pas l'Edge. */
    timeoutMs?: number
}

async function upstashCmd(
    opts: UpstashOptions,
    command: (string | number)[],
): Promise<unknown> {
    const ctrl = new AbortController()
    const timer = setTimeout(() => ctrl.abort(), opts.timeoutMs ?? 1500)
    try {
        const res = await fetch(opts.url, {
            method: 'POST',
            headers: {
                Authorization: `Bearer ${opts.token}`,
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(command),
            signal: ctrl.signal,
        })
        if (!res.ok) return null
        const json = await res.json() as { result?: unknown; error?: string }
        if (json.error) return null
        return json.result
    } catch {
        return null // fail-soft : l'appelant gère le repli
    } finally {
        clearTimeout(timer)
    }
}

/**
 * Crée un KvStore Upstash. Renvoie null si la config est absente
 * (l'appelant doit alors retomber sur MemoryKv).
 */
export function createUpstashKv(opts: Partial<UpstashOptions>): KvStore | null {
    if (!opts.url || !opts.token) return null
    const cfg: UpstashOptions = { url: opts.url, token: opts.token, timeoutMs: opts.timeoutMs }

    return {
        async incr(key: string, ttlSeconds: number): Promise<number> {
            const v = await upstashCmd(cfg, ['INCR', key])
            const count = typeof v === 'number' ? v : Number(v) || 1
            // Pose l'expiration uniquement au 1er incrément (fenêtre fixe)
            if (count === 1) {
                await upstashCmd(cfg, ['EXPIRE', key, ttlSeconds])
            }
            return count
        },
        async get(key: string): Promise<number | null> {
            const v = await upstashCmd(cfg, ['GET', key])
            if (v === null || v === undefined) return null
            const n = Number(v)
            return isNaN(n) ? null : n
        },
        async set(key: string, value: number, ttlSeconds: number): Promise<void> {
            await upstashCmd(cfg, ['SET', key, value, 'EX', ttlSeconds])
        },
        async del(key: string): Promise<void> {
            await upstashCmd(cfg, ['DEL', key])
        },
    }
}

/**
 * Helper : renvoie le store Upstash si configuré, sinon le fallback fourni.
 *   const kv = resolveKv(createUpstashKv(env), new MemoryKv())
 */
export function resolveKv(primary: KvStore | null, fallback: KvStore): KvStore {
    return primary ?? fallback
}
