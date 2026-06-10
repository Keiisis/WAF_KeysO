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
} from './adapters/nextjs'
export type {
    ScanRequestBodyResult,
    ScanRequestBodyOptions,
    AssertOwnershipParams,
    AssertOwnershipResult,
} from './adapters/nextjs'
