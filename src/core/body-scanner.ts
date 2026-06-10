// ══════════════════════════════════════════════════════════════
// 🛡️  @waf-core/body-scanner — Analyseur structurel de payload
// ══════════════════════════════════════════════════════════════
//
// PORTABLE — Zéro dépendance. Aucune référence à Next.js, Supabase,
// React ou tout framework. Pure logique TypeScript.
//
// Objectif : analyser un corps de requête DÉJÀ PARSÉ (objet JS issu
// d'un JSON, d'un form, d'un XML converti…) et détecter les attaques
// qui ne transitent pas par l'URL :
//   - Prototype Pollution        (__proto__, constructor.prototype)
//   - Désérialisation / RCE       (child_process, require, gadget chains)
//   - SSRF dans les valeurs       (IP internes, metadata cloud, schémas)
//   - DoS structurel              (profondeur récursive, explosion de clés)
//
// Ce module est conçu pour être réutilisé tel quel dans :
//   - Next.js / Node (import direct)
//   - Express / Fastify (import direct)
//   - WordPress / PHP (le RULESET ci-dessous sert de spécification de port)
//
// Usage :
//   import { scanBody, DEFAULT_SCAN_OPTIONS } from './core/body-scanner'
//   const verdict = scanBody(parsedJson)
//   if (!verdict.safe) { /* bloquer / logger / deception */ }
// ══════════════════════════════════════════════════════════════

export type BodyThreatType =
    | 'prototype_pollution'
    | 'rce_gadget'
    | 'ssrf_internal_target'
    | 'recursive_depth'
    | 'key_explosion'
    | 'array_explosion'
    | 'oversized_string'

export interface BodyScanVerdict {
    safe: boolean
    threat: BodyThreatType | null
    /** Confiance 0–100 (100 = certitude). */
    confidence: number
    /** Chemin JSON où la menace a été trouvée (ex: "user.profile.__proto__"). */
    path: string
    /** Message lisible pour le log. */
    detail: string
}

export interface BodyScanOptions {
    maxDepth: number            // profondeur max d'imbrication (anti-DoS)
    maxKeys: number             // nb total de clés autorisées (anti-DoS)
    maxArrayLength: number      // longueur max d'un tableau (anti-DoS)
    maxStringLength: number     // longueur max d'une string (anti-DoS / ReDoS feeder)
    checkPrototypePollution: boolean
    checkRce: boolean
    checkSsrf: boolean
}

export const DEFAULT_SCAN_OPTIONS: BodyScanOptions = {
    maxDepth: 24,
    maxKeys: 5000,
    maxArrayLength: 10000,
    maxStringLength: 50000,
    checkPrototypePollution: true,
    checkRce: true,
    checkSsrf: true,
}

// ── Clés dangereuses : prototype pollution ───────────────────────
// Toute clé d'objet portant un de ces noms est une tentative de
// pollution de prototype (RCE possible côté Node/V8).
const POLLUTION_KEYS = new Set(['__proto__', 'prototype', 'constructor'])

// ── Signatures RCE / désérialisation dans les valeurs string ─────
// Ces gadgets apparaissent dans les chaînes d'exploitation Node.js,
// les payloads de désérialisation et les SSTI.
const RCE_SIGNATURES: { re: RegExp; label: string; confidence: number }[] = [
    { re: /\bchild_process\b/i,                       label: 'child_process', confidence: 95 },
    { re: /\bprocess\.(?:mainModule|binding|env)\b/i, label: 'process internals', confidence: 95 },
    { re: /\brequire\s*\(\s*['"`]/i,                   label: 'require() call', confidence: 90 },
    { re: /\b(?:eval|Function)\s*\(/i,                 label: 'eval/Function ctor', confidence: 85 },
    { re: /\bglobal(?:This)?\s*\[/i,                   label: 'global object access', confidence: 80 },
    { re: /\b_\$\$ND_FUNC\$\$_/,                       label: 'node-serialize gadget', confidence: 98 }, // node-serialize RCE
    { re: /\{\{.*(?:constructor|process|require|global).*\}\}/i, label: 'SSTI gadget', confidence: 90 },
    { re: /\$\{.*(?:process|require|global).*\}/i,     label: 'template literal injection', confidence: 85 },
    { re: /\bruntime\b.*\bexec\b/i,                    label: 'Runtime.exec (Java gadget)', confidence: 90 },
]

// ── Détection SSRF dans les valeurs string ───────────────────────
// On extrait les hosts depuis les URLs présentes dans la valeur,
// puis on teste si l'hôte cible une ressource interne/cloud.
const URL_IN_STRING = /\b(?:https?|ftp|gopher|file|dict|ldap):\/\/([^\s/?#"']+)/gi
const CLOUD_METADATA_HOSTS = new Set([
    '169.254.169.254',          // AWS / GCP / Azure IMDS
    'metadata.google.internal',
    '100.100.200.200',          // Alibaba
    'metadata',
])

/**
 * Teste si un hôte (IP ou nom) cible une ressource interne.
 * Détection IP CORRECTE (octets parsés) — pas de match substring naïf
 * qui bloquerait "version 10.2" ou "prix 127.0 €".
 */
export function isInternalHost(host: string): boolean {
    const h = host.toLowerCase().replace(/:\d+$/, '').trim() // retire le port

    if (h === 'localhost' || h.endsWith('.localhost') || h === '0.0.0.0') return true
    if (h === '[::1]' || h === '::1') return true            // IPv6 loopback
    if (h.startsWith('[fc') || h.startsWith('[fd')) return true // IPv6 ULA fc00::/7
    if (h.startsWith('[fe80')) return true                   // IPv6 link-local
    if (CLOUD_METADATA_HOSTS.has(h)) return true

    // IPv4 : parser les 4 octets pour tester les vraies plages privées
    const m = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/)
    if (m) {
        const a = +m[1], b = +m[2]
        if (a > 255 || b > 255 || +m[3] > 255 || +m[4] > 255) return false
        if (a === 127) return true                           // 127.0.0.0/8 loopback
        if (a === 10) return true                            // 10.0.0.0/8
        if (a === 192 && b === 168) return true              // 192.168.0.0/16
        if (a === 172 && b >= 16 && b <= 31) return true     // 172.16.0.0/12 (PAS tout 172.x !)
        if (a === 169 && b === 254) return true              // 169.254.0.0/16 link-local + IMDS
        if (a === 100 && b >= 64 && b <= 127) return true    // 100.64.0.0/10 CGNAT
        if (a === 0) return true                             // 0.0.0.0/8
    }
    return false
}

/** Schémas d'URL dangereux pour SSRF (exfiltration, pivot). */
const DANGEROUS_SCHEMES = /\b(?:gopher|dict|file|ldap|ftp|jar|netdoc):\/\//i

function scanString(value: string, path: string, opts: BodyScanOptions): BodyScanVerdict | null {
    if (value.length > opts.maxStringLength) {
        return {
            safe: false, threat: 'oversized_string', confidence: 70, path,
            detail: `Chaîne de ${value.length} caractères (max ${opts.maxStringLength}) — possible DoS/ReDoS`,
        }
    }

    if (opts.checkRce) {
        for (const sig of RCE_SIGNATURES) {
            if (sig.re.test(value)) {
                return {
                    safe: false, threat: 'rce_gadget', confidence: sig.confidence, path,
                    detail: `Gadget RCE [${sig.label}] dans ${path}`,
                }
            }
        }
    }

    if (opts.checkSsrf) {
        if (DANGEROUS_SCHEMES.test(value)) {
            return {
                safe: false, threat: 'ssrf_internal_target', confidence: 85, path,
                detail: `Schéma d'URL dangereux dans ${path}`,
            }
        }
        URL_IN_STRING.lastIndex = 0
        let um: RegExpExecArray | null
        while ((um = URL_IN_STRING.exec(value)) !== null) {
            if (isInternalHost(um[1])) {
                return {
                    safe: false, threat: 'ssrf_internal_target', confidence: 92, path,
                    detail: `Cible interne/cloud-metadata "${um[1]}" dans ${path}`,
                }
            }
        }
    }

    return null
}

/**
 * Analyse récursive d'un payload déjà parsé.
 * Renvoie un verdict { safe } — ne lève jamais d'exception.
 */
export function scanBody(
    payload: unknown,
    options: Partial<BodyScanOptions> = {}
): BodyScanVerdict {
    const opts: BodyScanOptions = { ...DEFAULT_SCAN_OPTIONS, ...options }
    const safe: BodyScanVerdict = { safe: true, threat: null, confidence: 0, path: '', detail: '' }

    if (payload === null || payload === undefined) return safe
    if (typeof payload !== 'object' && typeof payload !== 'string') return safe

    let keyCount = 0

    // Pile explicite (évite un stack overflow sur payload hostile très profond)
    const stack: { node: unknown; depth: number; path: string }[] = [{ node: payload, depth: 0, path: '' }]

    while (stack.length > 0) {
        const { node, depth, path } = stack.pop()!

        if (depth > opts.maxDepth) {
            return {
                safe: false, threat: 'recursive_depth', confidence: 80, path,
                detail: `Profondeur d'imbrication > ${opts.maxDepth} — possible DoS JSON`,
            }
        }

        // String terminale
        if (typeof node === 'string') {
            const v = scanString(node, path || '(racine)', opts)
            if (v) return v
            continue
        }

        if (typeof node !== 'object' || node === null) continue

        // Tableau
        if (Array.isArray(node)) {
            if (node.length > opts.maxArrayLength) {
                return {
                    safe: false, threat: 'array_explosion', confidence: 75, path,
                    detail: `Tableau de ${node.length} éléments (max ${opts.maxArrayLength}) — possible DoS`,
                }
            }
            for (let i = 0; i < node.length; i++) {
                stack.push({ node: node[i], depth: depth + 1, path: `${path}[${i}]` })
            }
            continue
        }

        // Objet — vérifier les clés (prototype pollution) puis descendre
        // On lit les clés brutes, y compris non-énumérables potentielles via getOwnPropertyNames
        const keys = Object.getOwnPropertyNames(node as Record<string, unknown>)
        for (const key of keys) {
            keyCount++
            if (keyCount > opts.maxKeys) {
                return {
                    safe: false, threat: 'key_explosion', confidence: 75, path,
                    detail: `Plus de ${opts.maxKeys} clés au total — possible DoS structurel`,
                }
            }

            if (opts.checkPrototypePollution && POLLUTION_KEYS.has(key)) {
                return {
                    safe: false, threat: 'prototype_pollution', confidence: 98,
                    path: path ? `${path}.${key}` : key,
                    detail: `Clé de pollution de prototype "${key}" détectée`,
                }
            }

            stack.push({
                node: (node as Record<string, unknown>)[key],
                depth: depth + 1,
                path: path ? `${path}.${key}` : key,
            })
        }
    }

    return safe
}
