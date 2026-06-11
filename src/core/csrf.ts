// ══════════════════════════════════════════════════════════════
// 🎫  KeysO-WAF · core/csrf — Protection CSRF (double-submit + origin)
// ══════════════════════════════════════════════════════════════
//
// Deux couches complémentaires, sans état serveur :
//   1. Vérification Origin/Referer vs hôtes autorisés (rapide, robuste).
//   2. Double-submit cookie : un token signé est posé en cookie ET doit
//      être renvoyé dans un header/champ ; les deux doivent correspondre.
//
// PORTABLE — zéro dépendance (utilise Web Crypto si dispo, sinon fallback).
// ══════════════════════════════════════════════════════════════

export interface CsrfOriginResult {
    valid: boolean
    reason: string
}

/** Méthodes considérées comme sûres (pas de vérif CSRF). */
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS', 'TRACE'])

/**
 * Vérifie l'Origin (ou Referer en repli) contre une liste d'hôtes autorisés.
 * @param method   méthode HTTP
 * @param origin   header Origin (peut être null)
 * @param referer  header Referer (peut être null)
 * @param allowedHosts hôtes autorisés (ex: ['example.com', 'www.example.com'])
 */
export function checkOrigin(
    method: string,
    origin: string | null,
    referer: string | null,
    allowedHosts: string[],
): CsrfOriginResult {
    if (SAFE_METHODS.has(method.toUpperCase())) {
        return { valid: true, reason: 'safe_method' }
    }
    const source = origin || referer
    if (!source) {
        // Pas d'Origin ni Referer sur une requête mutante = suspect
        return { valid: false, reason: 'missing_origin_and_referer' }
    }
    let host: string
    try {
        host = new URL(source).host.toLowerCase()
    } catch {
        return { valid: false, reason: 'malformed_origin' }
    }
    const ok = allowedHosts.some(h => h.toLowerCase() === host)
    return ok
        ? { valid: true, reason: 'origin_allowed' }
        : { valid: false, reason: `origin_not_allowed:${host}` }
}

/** Compare deux tokens en temps constant (anti timing-attack). */
export function constantTimeEqual(a: string, b: string): boolean {
    if (a.length !== b.length) return false
    let diff = 0
    for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i)
    return diff === 0
}

/**
 * Vérifie un double-submit token : le token du cookie doit égaler celui
 * fourni dans le header/champ. (La signature/rotation est gérée côté app ;
 * ici on garantit l'égalité en temps constant + non-vacuité.)
 */
export function checkDoubleSubmit(
    cookieToken: string | null | undefined,
    submittedToken: string | null | undefined,
): CsrfOriginResult {
    if (!cookieToken || !submittedToken) {
        return { valid: false, reason: 'missing_csrf_token' }
    }
    if (cookieToken.length < 16) {
        return { valid: false, reason: 'weak_csrf_token' }
    }
    return constantTimeEqual(cookieToken, submittedToken)
        ? { valid: true, reason: 'token_match' }
        : { valid: false, reason: 'token_mismatch' }
}

/** Génère un token CSRF aléatoire (hex). Web Crypto si dispo. */
export function generateCsrfToken(bytes = 32): string {
    const g = (globalThis as { crypto?: Crypto }).crypto
    if (g && typeof g.getRandomValues === 'function') {
        const arr = new Uint8Array(bytes)
        g.getRandomValues(arr)
        return Array.from(arr, b => b.toString(16).padStart(2, '0')).join('')
    }
    // Fallback non-cryptographique (dev only)
    let s = ''
    for (let i = 0; i < bytes * 2; i++) s += Math.floor(Math.random() * 16).toString(16)
    return s
}
