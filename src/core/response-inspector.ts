// ══════════════════════════════════════════════════════════════
// 🔍  KeysO-WAF · core/response-inspector — Fuite de données sortante
// ══════════════════════════════════════════════════════════════
//
// Inspecte le CORPS d'une RÉPONSE avant de l'envoyer au client, pour
// détecter (et masquer/bloquer) les fuites involontaires :
//   - Stack traces / erreurs de framework (chemins serveur, lignes)
//   - Erreurs SQL brutes (exposent le schéma)
//   - Secrets / clés (AWS, Stripe, JWT, clés privées, tokens)
//   - PII en masse (emails, cartes bancaires, IBAN)
//   - Chemins internes / infos de debug
//
// Usage : inspectResponse(text) → { leaks: [...], redacted }
// PORTABLE — zéro dépendance.
// ══════════════════════════════════════════════════════════════

export type LeakType =
    | 'stack_trace'
    | 'sql_error'
    | 'secret_key'
    | 'private_key'
    | 'jwt'
    | 'credit_card'
    | 'iban'
    | 'internal_path'
    | 'debug_info'
    | 'pii_email_bulk'

export interface ResponseLeak {
    type: LeakType
    severity: number      // 1..4
    sample: string        // extrait (déjà tronqué)
    count: number
}

export interface ResponseInspectVerdict {
    safe: boolean
    leaks: ResponseLeak[]
    /** Réponse avec les fuites masquées (si redact demandé). */
    redacted?: string
    highestSeverity: number
}

interface LeakRule {
    type: LeakType
    severity: number
    re: RegExp
    /** Remplacement de masquage. */
    mask: string
}

// Cartes bancaires : 13–19 chiffres (avec séparateurs) — validées par Luhn ensuite.
const CARD_RE = /\b(?:\d[ -]?){13,19}\b/g

const RULES: LeakRule[] = [
    { type: 'private_key', severity: 4, mask: '«clé privée masquée»',
      re: /-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]+?-----END/g },
    { type: 'secret_key', severity: 4, mask: '«secret masqué»',
      re: /\b(?:AKIA[0-9A-Z]{16}|sk_live_[0-9a-zA-Z]{16,}|rk_live_[0-9a-zA-Z]{16,}|xox[baprs]-[0-9a-zA-Z-]{10,}|ghp_[0-9A-Za-z]{36}|AIza[0-9A-Za-z\-_]{35})\b/g },
    { type: 'jwt', severity: 3, mask: '«jwt masqué»',
      re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g },
    { type: 'stack_trace', severity: 3, mask: '«trace masquée»',
      re: /(?:\bat\s+[\w.$<>]+\s+\([^)]*:\d+:\d+\)|Traceback \(most recent call last\)|Fatal error:.*on line \d+|#\d+\s+\/[^\s]+\(\d+\):)/g },
    { type: 'sql_error', severity: 3, mask: '«erreur SQL masquée»',
      re: /\b(?:SQLSTATE\[|You have an error in your SQL syntax|PG::\w+Error|ORA-\d{5}|SQLite3::|near ".*": syntax error|Unknown column '[^']+' in)/gi },
    { type: 'iban', severity: 3, mask: '«IBAN masqué»',
      re: /\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}[ ]?[A-Z0-9]{1,3}\b/g },
    { type: 'internal_path', severity: 2, mask: '«chemin masqué»',
      re: /\b(?:\/(?:var\/www|home\/\w+|usr\/local|etc\/(?:passwd|shadow))|[A-Z]:\\(?:inetpub|xampp|wamp|Users\\[^\\]+\\))[^\s"']*/g },
    { type: 'debug_info', severity: 1, mask: '«debug masqué»',
      re: /\b(?:DEBUG\s*=\s*true|X-Debug-Token|Symfony\\Component|Laravel\\|\$_SERVER\[|var_dump\(|print_r\()/g },
]

function luhnValid(num: string): boolean {
    const d = num.replace(/\D/g, '')
    if (d.length < 13 || d.length > 19) return false
    let sum = 0, alt = false
    for (let i = d.length - 1; i >= 0; i--) {
        let n = +d[i]
        if (alt) { n *= 2; if (n > 9) n -= 9 }
        sum += n; alt = !alt
    }
    return sum % 10 === 0
}

const EMAIL_RE = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g
const EMAIL_BULK_THRESHOLD = 25  // au-delà = dump de base probable

function trunc(s: string, n = 60): string {
    return s.length > n ? s.slice(0, n) + '…' : s
}

/**
 * Inspecte un texte de réponse. Ne lève jamais.
 * @param text       corps de la réponse
 * @param opts.redact si true, renvoie une version masquée
 */
export function inspectResponse(
    text: string,
    opts: { redact?: boolean } = {}
): ResponseInspectVerdict {
    const leaks: ResponseLeak[] = []
    let redacted = text

    for (const rule of RULES) {
        const matches = text.match(rule.re)
        if (matches && matches.length > 0) {
            leaks.push({ type: rule.type, severity: rule.severity, sample: trunc(matches[0]), count: matches.length })
            if (opts.redact) redacted = redacted.replace(rule.re, rule.mask)
        }
    }

    // Cartes bancaires (Luhn pour éviter les faux positifs sur les longs nombres)
    const cardCandidates = text.match(CARD_RE) || []
    const validCards = cardCandidates.filter(luhnValid)
    if (validCards.length > 0) {
        leaks.push({ type: 'credit_card', severity: 4, sample: trunc(validCards[0]), count: validCards.length })
        if (opts.redact) for (const c of validCards) redacted = redacted.split(c).join('«carte masquée»')
    }

    // Fuite massive d'emails (dump)
    const emails = text.match(EMAIL_RE) || []
    const uniqueEmails = new Set(emails.map(e => e.toLowerCase()))
    if (uniqueEmails.size >= EMAIL_BULK_THRESHOLD) {
        leaks.push({ type: 'pii_email_bulk', severity: 3, sample: `${uniqueEmails.size} emails distincts`, count: uniqueEmails.size })
    }

    const highestSeverity = leaks.reduce((m, l) => Math.max(m, l.severity), 0)
    return {
        safe: leaks.length === 0,
        leaks,
        highestSeverity,
        ...(opts.redact ? { redacted } : {}),
    }
}
