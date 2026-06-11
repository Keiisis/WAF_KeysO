// ══════════════════════════════════════════════════════════════
// 🌐  KeysO-WAF · core/client-ip — Extraction d'IP anti-spoofing
// ══════════════════════════════════════════════════════════════
//
// Problème : faire confiance aveuglément à `X-Forwarded-For` /
// `CF-Connecting-IP` permet à un attaquant de SPOOFER son IP (évasion de
// ban, ou empoisonnement de l'IP d'un tiers pour le faire bannir).
//
// Règle : on ne fait confiance à un header de forwarding QUE si le pair
// immédiat (l'IP du socket / proxy qui se connecte à nous) est un proxy
// de CONFIANCE déclaré. Sinon, on retombe sur l'IP du socket.
//
// Sémantique XFF : `client, proxy1, proxy2`. On parcourt de DROITE à
// GAUCHE et on renvoie la première IP qui n'est PAS un proxy de confiance
// (= le vrai client, le plus à droite que l'attaquant ne contrôle plus).
//
// PORTABLE — zéro dépendance.
// ══════════════════════════════════════════════════════════════

export interface ClientIpOptions {
    /** IP du pair immédiat (REMOTE_ADDR / socket.remoteAddress). */
    socketIp: string
    /** Map de headers (clé en minuscules). */
    headers: Record<string, string | undefined> | Headers
    /**
     * Proxies de confiance : IPs exactes ou CIDR (ex: '10.0.0.0/8',
     * '173.245.48.0/20'). Si VIDE → aucun header de forwarding n'est cru.
     */
    trustedProxies?: string[]
    /**
     * Ordre des headers de forwarding à consulter (si le socket est de confiance).
     * Défaut : CF-Connecting-IP, True-Client-IP, X-Real-IP, X-Forwarded-For.
     */
    headerPriority?: string[]
}

const DEFAULT_HEADERS = ['cf-connecting-ip', 'true-client-ip', 'x-real-ip', 'x-forwarded-for']

function readHeader(headers: ClientIpOptions['headers'], name: string): string | undefined {
    if (typeof (headers as Headers).get === 'function') {
        return (headers as Headers).get(name) ?? undefined
    }
    const h = headers as Record<string, string | undefined>
    return h[name] ?? h[name.toLowerCase()] ?? undefined
}

/** Valide grossièrement une IPv4/IPv6. */
export function isValidIp(ip: string): boolean {
    const s = ip.trim()
    if (/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.test(s)) {
        return s.split('.').every(o => +o >= 0 && +o <= 255)
    }
    // IPv6 (forme simple, sans validation exhaustive)
    return /^[0-9a-f:]+$/i.test(s) && s.includes(':')
}

function ipv4ToInt(ip: string): number | null {
    const m = ip.trim().match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/)
    if (!m) return null
    const o = [ +m[1], +m[2], +m[3], +m[4] ]
    if (o.some(x => x > 255)) return null
    return ((o[0] << 24) >>> 0) + (o[1] << 16) + (o[2] << 8) + o[3]
}

/** Teste si une IPv4 appartient à un CIDR ou égale une IP exacte. */
export function ipMatches(ip: string, ruleCidrOrIp: string): boolean {
    const rule = ruleCidrOrIp.trim()
    if (rule === ip.trim()) return true
    if (!rule.includes('/')) return false
    const [net, bitsStr] = rule.split('/')
    const bits = parseInt(bitsStr, 10)
    const ipInt = ipv4ToInt(ip)
    const netInt = ipv4ToInt(net)
    if (ipInt === null || netInt === null || isNaN(bits) || bits < 0 || bits > 32) return false
    if (bits === 0) return true
    const mask = bits === 32 ? 0xffffffff : (~((1 << (32 - bits)) - 1)) >>> 0
    return (ipInt & mask) === (netInt & mask)
}

function isTrusted(ip: string, trusted: string[]): boolean {
    return trusted.some(rule => ipMatches(ip, rule))
}

/**
 * Résout l'IP client réelle, résistante au spoofing.
 * Retourne toujours une IP (le socket en dernier recours).
 */
export function resolveClientIp(opts: ClientIpOptions): string {
    const socket = (opts.socketIp || '').trim()
    const trusted = opts.trustedProxies ?? []

    // Pas de proxy de confiance déclaré → on NE croit AUCUN header (anti-spoof strict)
    if (trusted.length === 0) {
        return socket || 'unknown'
    }

    // Le pair immédiat n'est pas un proxy de confiance → un attaquant direct :
    // ses headers de forwarding sont mensongers, on garde le socket.
    if (socket && !isTrusted(socket, trusted)) {
        return socket
    }

    const priority = opts.headerPriority ?? DEFAULT_HEADERS

    // X-Forwarded-For : parcourir de droite à gauche, sauter les proxies de confiance
    const xff = readHeader(opts.headers, 'x-forwarded-for')
    if (xff) {
        const chain = xff.split(',').map(s => s.trim()).filter(Boolean)
        for (let i = chain.length - 1; i >= 0; i--) {
            const candidate = chain[i]
            if (isValidIp(candidate) && !isTrusted(candidate, trusted)) {
                return candidate // premier non-proxy = vrai client
            }
        }
    }

    // Headers single-value (CF/Real-IP) — fiables car le socket est de confiance
    for (const name of priority) {
        if (name === 'x-forwarded-for') continue
        const v = readHeader(opts.headers, name)
        if (v) {
            const first = v.split(',')[0].trim()
            if (isValidIp(first)) return first
        }
    }

    return socket || 'unknown'
}
