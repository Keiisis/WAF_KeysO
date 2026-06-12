// ══════════════════════════════════════════════════════════════
// KeysO-WAF — Point d'entrée du SDK
// ══════════════════════════════════════════════════════════════
//
// CORE (portable, zéro dépendance) :
export {
    scanBody,
    isInternalHost,
    DEFAULT_SCAN_OPTIONS,
} from './core/body-scanner'
export type {
    BodyScanVerdict,
    BodyScanOptions,
    BodyThreatType,
} from './core/body-scanner'

export { verifyOwnership } from './core/ownership'
export type {
    OwnershipResolver,
    OwnershipQuery,
    OwnershipResolution,
    OwnershipVerdict,
    OwnershipDecision,
    MissingResourcePolicy,
    VerifyOwnershipOptions,
} from './core/ownership'

// ADAPTERS (couche jetable — dépendances en peerDependencies) :
export {
    createSupabaseOwnershipResolver,
    EXAMPLE_RESOURCE_MAP,
} from './adapters/supabase-ownership'
export type { ResourceMap, ResourceMapEntry } from './adapters/supabase-ownership'

export {
    scanRequestBody,
    assertOwnership,
    withWafGuard,
} from './adapters/nextjs'
export type {
    ScanRequestBodyResult,
    ScanRequestBodyOptions,
    AssertOwnershipParams,
    AssertOwnershipResult,
    WafGuardOptions,
} from './adapters/nextjs'

// ── RLS engine portable (indépendant de Supabase) ──
export {
    evaluateAccess,
    evaluateCondition,
    filterReadable,
    assertWritable,
    TRUE, FALSE, owner, eq, and, or, ref,
} from './core/rls'
export type {
    RlsAuth, RlsAction, RlsRef, RlsValue,
    RlsCondition, RlsPolicy, RlsContext, RlsVerdict,
} from './core/rls'

// ── Extraction d'IP anti-spoofing ──
export { resolveClientIp, ipMatches, isValidIp } from './core/client-ip'
export type { ClientIpOptions } from './core/client-ip'

// ── Tarpit borné (anti auto-DoS) ──
export { boundedTarpit, tarpitDelayForTrust, tarpitMetrics } from './core/tarpit'
export type { TarpitOptions, TarpitResult } from './core/tarpit'

// ── CSRF ──
export { checkOrigin, checkDoubleSubmit, generateCsrfToken, constantTimeEqual } from './core/csrf'
export type { CsrfOriginResult } from './core/csrf'

// ── Upload scanner ──
export { scanUpload } from './core/upload-scanner'
export type { UploadInput, UploadScanVerdict, UploadThreat } from './core/upload-scanner'

// ── Inspection des réponses (data leakage sortant) ──
export { inspectResponse } from './core/response-inspector'
export type { ResponseInspectVerdict, ResponseLeak, LeakType } from './core/response-inspector'

// ── Anomalies d'authentification (credential-stuffing + impossible travel) ──
export {
    detectCredentialStuffing,
    detectImpossibleTravel,
    haversineKm,
} from './core/auth-anomaly'
export type {
    LoginAttempt, StuffingVerdict, StuffingThresholds,
    GeoLogin, TravelVerdict,
} from './core/auth-anomaly'
