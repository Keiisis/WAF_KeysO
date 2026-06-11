// ══════════════════════════════════════════════════════════════
// 🔒  KeysO-WAF · core/rls — Moteur Row-Level Security PORTABLE
// ══════════════════════════════════════════════════════════════
//
// Un moteur de politiques d'accès au niveau ligne, INDÉPENDANT de
// Supabase/Postgres. Les policies sont des DONNÉES (pas du SQL), évaluées
// par un interpréteur sûr (zéro `eval`, zéro dépendance).
//
// Sémantique alignée sur Postgres RLS :
//   - Politiques PERMISSIVES : une ligne est autorisée si AU MOINS UNE
//     politique applicable (table + action + rôle) passe.
//   - `using`  : visibilité (select/update/delete) — filtre les lignes lues.
//   - `check`  : écriture (insert/update) — valide la ligne écrite.
//   - DEFAULT DENY : aucune politique applicable ⇒ refus.
//
// Pourquoi dans un WAF ? Pour porter l'autorisation au niveau ligne sur
// des stacks qui n'ont pas de RLS natif (MySQL/WordPress, Mongo, API REST
// tierces), et garder une logique d'accès unique, testable, auditable.
//
// Usage :
//   const policies: RlsPolicy[] = [
//     { name:'own_invoices', table:'invoices', action:'select',
//       using: owner('user_id') },
//     { name:'staff_all', table:'invoices', action:'*',
//       role:'admin', using: TRUE },
//   ]
//   const auth = { uid:'u1', role:'client' }
//   evaluateAccess(policies, { table:'invoices', action:'select', row, auth })
//   filterReadable(policies, { table:'invoices', action:'select', auth }, rows)
// ══════════════════════════════════════════════════════════════

/** Contexte d'authentification injecté (qui fait la requête). */
export interface RlsAuth {
    uid: string | null
    role?: string | null
    /** Claims additionnels accessibles via ref 'auth.<key>'. */
    claims?: Record<string, unknown>
}

export type RlsAction = 'select' | 'insert' | 'update' | 'delete' | '*'

/** Référence dynamique résolue depuis le contexte auth. */
export interface RlsRef {
    ref: string // 'auth.uid' | 'auth.role' | 'auth.claims.org_id' | ...
}

export type RlsValue = string | number | boolean | null | RlsRef | RlsValue[]

/** Condition — AST sûr, jamais évalué via eval(). */
export type RlsCondition =
    | { op: 'true' }
    | { op: 'false' }
    | { op: 'eq' | 'ne' | 'lt' | 'lte' | 'gt' | 'gte'; field: string; value: RlsValue }
    | { op: 'in'; field: string; value: RlsValue[] | RlsRef }
    | { op: 'contains'; field: string; value: RlsValue }   // field (array/string) contient value
    | { op: 'owner'; field: string }                       // row[field] === auth.uid
    | { op: 'and' | 'or'; conditions: RlsCondition[] }
    | { op: 'not'; condition: RlsCondition }

export interface RlsPolicy {
    name: string
    table: string
    action: RlsAction
    /** Rôle(s) autorisé(s). Absent = tous rôles. */
    role?: string | string[]
    /** Visibilité (select/update/delete). Absent = TRUE. */
    using?: RlsCondition
    /** Validation d'écriture (insert/update). Absent = identique à `using` ou TRUE. */
    check?: RlsCondition
}

export interface RlsContext {
    table: string
    action: Exclude<RlsAction, '*'>
    auth: RlsAuth
    /** La ligne concernée (présente pour eval unitaire). */
    row?: Record<string, unknown>
}

export interface RlsVerdict {
    allowed: boolean
    /** Nom de la politique qui a accordé l'accès (le cas échéant). */
    matchedPolicy: string | null
    reason: string
}

// ── Helpers d'écriture de policies (sucre syntaxique) ────────────
export const TRUE: RlsCondition = { op: 'true' }
export const FALSE: RlsCondition = { op: 'false' }
export const owner = (field: string): RlsCondition => ({ op: 'owner', field })
export const eq = (field: string, value: RlsValue): RlsCondition => ({ op: 'eq', field, value })
export const and = (...conditions: RlsCondition[]): RlsCondition => ({ op: 'and', conditions })
export const or = (...conditions: RlsCondition[]): RlsCondition => ({ op: 'or', conditions })
export const ref = (path: string): RlsRef => ({ ref: path })

// ── Résolution de chemins ────────────────────────────────────────
function getPath(obj: unknown, path: string): unknown {
    if (obj == null) return undefined
    let cur: unknown = obj
    for (const part of path.split('.')) {
        if (cur == null || typeof cur !== 'object') return undefined
        cur = (cur as Record<string, unknown>)[part]
    }
    return cur
}

/** Résout une RlsValue : littéral, ref vers auth, ou tableau. */
function resolveValue(value: RlsValue, auth: RlsAuth): unknown {
    if (value !== null && typeof value === 'object' && !Array.isArray(value) && 'ref' in value) {
        const path = (value as RlsRef).ref
        if (path === 'auth.uid') return auth.uid
        if (path === 'auth.role') return auth.role ?? null
        if (path.startsWith('auth.claims.')) return getPath(auth.claims ?? {}, path.slice('auth.claims.'.length))
        if (path.startsWith('auth.')) return getPath({ uid: auth.uid, role: auth.role, ...auth.claims }, path.slice(5))
        return undefined
    }
    if (Array.isArray(value)) return value.map(v => resolveValue(v, auth))
    return value
}

function cmp(a: unknown, b: unknown): number | null {
    if (typeof a === 'number' && typeof b === 'number') return a - b
    if (typeof a === 'string' && typeof b === 'string') return a < b ? -1 : a > b ? 1 : 0
    // dates ISO
    const da = Date.parse(String(a)), db = Date.parse(String(b))
    if (!isNaN(da) && !isNaN(db)) return da - db
    return null
}

/**
 * Évalue une condition contre une ligne + un contexte auth.
 * Ne lève jamais ; une condition mal formée renvoie false (fail-closed).
 */
export function evaluateCondition(
    cond: RlsCondition | undefined,
    row: Record<string, unknown>,
    auth: RlsAuth,
): boolean {
    if (!cond) return true // pas de condition = autorisé (équiv. USING true)
    try {
        switch (cond.op) {
            case 'true':  return true
            case 'false': return false
            case 'owner': {
                const v = getPath(row, cond.field)
                return v != null && auth.uid != null && String(v) === String(auth.uid)
            }
            case 'eq':  return String(getPath(row, cond.field)) === String(resolveValue(cond.value, auth))
            case 'ne':  return String(getPath(row, cond.field)) !== String(resolveValue(cond.value, auth))
            case 'lt': case 'lte': case 'gt': case 'gte': {
                const c = cmp(getPath(row, cond.field), resolveValue(cond.value, auth))
                if (c === null) return false
                return cond.op === 'lt' ? c < 0 : cond.op === 'lte' ? c <= 0 : cond.op === 'gt' ? c > 0 : c >= 0
            }
            case 'in': {
                const list = resolveValue(cond.value as RlsValue, auth)
                const target = getPath(row, cond.field)
                return Array.isArray(list) && list.some(x => String(x) === String(target))
            }
            case 'contains': {
                const field = getPath(row, cond.field)
                const needle = resolveValue(cond.value, auth)
                if (Array.isArray(field)) return field.some(x => String(x) === String(needle))
                if (typeof field === 'string') return field.includes(String(needle))
                return false
            }
            case 'and': return cond.conditions.every(c => evaluateCondition(c, row, auth))
            case 'or':  return cond.conditions.some(c => evaluateCondition(c, row, auth))
            case 'not': return !evaluateCondition(cond.condition, row, auth)
            default:    return false
        }
    } catch {
        return false // fail-closed
    }
}

function roleMatches(policy: RlsPolicy, role: string | null | undefined): boolean {
    if (policy.role === undefined) return true
    const allowed = Array.isArray(policy.role) ? policy.role : [policy.role]
    return role != null && allowed.includes(role)
}

function actionMatches(policy: RlsPolicy, action: RlsAction): boolean {
    return policy.action === '*' || policy.action === action
}

/** Politiques applicables à (table, action, rôle). */
function applicable(policies: RlsPolicy[], ctx: RlsContext): RlsPolicy[] {
    return policies.filter(p =>
        p.table === ctx.table &&
        actionMatches(p, ctx.action) &&
        roleMatches(p, ctx.auth.role)
    )
}

/**
 * Décision d'accès sur UNE ligne. Sémantique permissive (OR des policies).
 * - select/delete : on évalue `using`.
 * - insert        : on évalue `check` (ou TRUE si absent).
 * - update        : on évalue `using` ET `check` (visibilité + écriture).
 */
export function evaluateAccess(policies: RlsPolicy[], ctx: RlsContext): RlsVerdict {
    const row = ctx.row ?? {}
    const pols = applicable(policies, ctx)
    if (pols.length === 0) {
        return { allowed: false, matchedPolicy: null, reason: `Aucune politique pour ${ctx.table}.${ctx.action} (rôle=${ctx.auth.role ?? '∅'}) — DEFAULT DENY` }
    }

    for (const p of pols) {
        let ok: boolean
        if (ctx.action === 'insert') {
            ok = evaluateCondition(p.check ?? p.using ?? TRUE, row, ctx.auth)
        } else if (ctx.action === 'update') {
            ok = evaluateCondition(p.using, row, ctx.auth) && evaluateCondition(p.check ?? p.using ?? TRUE, row, ctx.auth)
        } else {
            ok = evaluateCondition(p.using, row, ctx.auth)
        }
        if (ok) {
            return { allowed: true, matchedPolicy: p.name, reason: `Autorisé par la politique "${p.name}"` }
        }
    }
    return { allowed: false, matchedPolicy: null, reason: `Aucune politique permissive ne couvre cette ligne` }
}

/**
 * Filtre une liste de lignes pour ne garder que celles visibles (select).
 * Équivalent du masquage RLS au niveau résultat.
 */
export function filterReadable<T extends Record<string, unknown>>(
    policies: RlsPolicy[],
    ctx: Omit<RlsContext, 'row'>,
    rows: T[],
): T[] {
    return rows.filter(row => evaluateAccess(policies, { ...ctx, row }).allowed)
}

/** Valide un lot d'insertions/updates ; renvoie la 1re ligne refusée s'il y en a. */
export function assertWritable(
    policies: RlsPolicy[],
    ctx: Omit<RlsContext, 'row'>,
    rows: Record<string, unknown>[],
): { ok: boolean; rejectedIndex: number; reason: string } {
    for (let i = 0; i < rows.length; i++) {
        const v = evaluateAccess(policies, { ...ctx, row: rows[i] })
        if (!v.allowed) return { ok: false, rejectedIndex: i, reason: v.reason }
    }
    return { ok: true, rejectedIndex: -1, reason: 'OK' }
}
