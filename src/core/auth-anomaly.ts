// ══════════════════════════════════════════════════════════════
// 🔑  KeysO-WAF · core/auth-anomaly — Credential-stuffing + Impossible travel
// ══════════════════════════════════════════════════════════════
//
// Détection d'anomalies d'authentification SANS API externe :
//   - Credential-stuffing / password-spray : une IP qui tente beaucoup
//     d'utilisateurs DIFFÉRENTS (spray), ou un compte attaqué depuis
//     beaucoup d'IP (stuffing distribué).
//   - Impossible travel : deux connexions réussies trop éloignées
//     géographiquement pour le temps écoulé (vitesse > avion).
//
// État injecté (store) → portable serverless (DB/Redis) ou en mémoire.
// La géoloc est FOURNIE par l'appelant (ex: headers CF cf-iplatitude/
// cf-iplongitude) → zéro appel réseau ici.
//
// PORTABLE — zéro dépendance.
// ══════════════════════════════════════════════════════════════

// ── Credential-stuffing / spray ──────────────────────────────────

export interface LoginAttempt {
    ip: string
    username: string
    success: boolean
    at: number // epoch ms
}

export interface StuffingVerdict {
    suspicious: boolean
    pattern: 'password_spray' | 'distributed_stuffing' | 'none'
    detail: string
    confidence: number
}

export interface StuffingThresholds {
    /** Fenêtre d'analyse (ms). Défaut 10 min. */
    windowMs?: number
    /** Nb d'usernames distincts depuis une IP avant alerte. Défaut 8. */
    distinctUsersPerIp?: number
    /** Nb d'IP distinctes ciblant un username avant alerte. Défaut 5. */
    distinctIpsPerUser?: number
}

/**
 * Analyse une fenêtre d'attempts (déjà filtrée par l'appelant ou complète).
 * Pure : on lui passe les attempts récents, elle calcule le verdict.
 */
export function detectCredentialStuffing(
    attempts: LoginAttempt[],
    focus: { ip?: string; username?: string },
    thresholds: StuffingThresholds = {}
): StuffingVerdict {
    const windowMs = thresholds.windowMs ?? 10 * 60_000
    const distinctUsersPerIp = thresholds.distinctUsersPerIp ?? 8
    const distinctIpsPerUser = thresholds.distinctIpsPerUser ?? 5
    const now = Date.now()
    const recent = attempts.filter(a => now - a.at <= windowMs)

    // Password spray : une IP, beaucoup d'usernames (surtout des échecs)
    if (focus.ip) {
        const fromIp = recent.filter(a => a.ip === focus.ip)
        const users = new Set(fromIp.map(a => a.username.toLowerCase()))
        const failures = fromIp.filter(a => !a.success).length
        if (users.size >= distinctUsersPerIp && failures >= distinctUsersPerIp) {
            return {
                suspicious: true, pattern: 'password_spray',
                detail: `IP ${focus.ip} a tenté ${users.size} comptes distincts (${failures} échecs) en ${Math.round(windowMs / 60000)} min`,
                confidence: Math.min(98, 70 + users.size * 2),
            }
        }
    }

    // Stuffing distribué : un username, beaucoup d'IP
    if (focus.username) {
        const onUser = recent.filter(a => a.username.toLowerCase() === focus.username!.toLowerCase())
        const ips = new Set(onUser.map(a => a.ip))
        const failures = onUser.filter(a => !a.success).length
        if (ips.size >= distinctIpsPerUser && failures >= distinctIpsPerUser) {
            return {
                suspicious: true, pattern: 'distributed_stuffing',
                detail: `Compte "${focus.username}" ciblé depuis ${ips.size} IP distinctes (${failures} échecs)`,
                confidence: Math.min(98, 70 + ips.size * 3),
            }
        }
    }

    return { suspicious: false, pattern: 'none', detail: '', confidence: 0 }
}

// ── Impossible travel ────────────────────────────────────────────

export interface GeoLogin {
    lat: number
    lon: number
    at: number // epoch ms
    label?: string // ex: ville/pays
}

export interface TravelVerdict {
    impossible: boolean
    distanceKm: number
    hours: number
    speedKmh: number
    detail: string
}

/** Distance haversine (km) entre deux points. */
export function haversineKm(a: { lat: number; lon: number }, b: { lat: number; lon: number }): number {
    const R = 6371
    const toRad = (d: number) => (d * Math.PI) / 180
    const dLat = toRad(b.lat - a.lat)
    const dLon = toRad(b.lon - a.lon)
    const lat1 = toRad(a.lat), lat2 = toRad(b.lat)
    const h = Math.sin(dLat / 2) ** 2 + Math.sin(dLon / 2) ** 2 * Math.cos(lat1) * Math.cos(lat2)
    return 2 * R * Math.asin(Math.min(1, Math.sqrt(h)))
}

/**
 * Détecte un déplacement impossible entre deux connexions.
 * @param maxSpeedKmh vitesse plafond plausible (défaut 1000 km/h ≈ avion ligne).
 */
export function detectImpossibleTravel(
    previous: GeoLogin,
    current: GeoLogin,
    maxSpeedKmh = 1000
): TravelVerdict {
    const distanceKm = haversineKm(previous, current)
    const hours = Math.abs(current.at - previous.at) / 3_600_000
    // En deçà de 60 km on ignore (imprécision GeoIP en zone urbaine).
    if (distanceKm < 60) {
        return { impossible: false, distanceKm, hours, speedKmh: 0, detail: 'distance intra-urbaine, ignorée' }
    }
    const speedKmh = hours > 0 ? distanceKm / hours : Infinity
    const impossible = speedKmh > maxSpeedKmh
    return {
        impossible,
        distanceKm: Math.round(distanceKm),
        hours: Math.round(hours * 100) / 100,
        speedKmh: Math.round(speedKmh),
        detail: impossible
            ? `Déplacement impossible : ${Math.round(distanceKm)} km en ${hours.toFixed(2)} h (${Math.round(speedKmh)} km/h)`
            : 'déplacement plausible',
    }
}
