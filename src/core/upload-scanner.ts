// ══════════════════════════════════════════════════════════════
// 📎  KeysO-WAF · core/upload-scanner — Analyse de fichiers uploadés
// ══════════════════════════════════════════════════════════════
//
// Détecte les uploads malveillants AVANT stockage :
//   - Double extension / extension exécutable masquée (shell.php.jpg)
//   - Path traversal dans le nom (../, chemins absolus, null byte)
//   - Incohérence MIME déclaré vs signature réelle (magic bytes)
//   - SVG/HTML/XML contenant du script (XSS stocké)
//   - Polyglotes (PHP/JS planqué dans un fichier image)
//   - PHP/scripts serveur dans des fichiers "inoffensifs"
//
// PORTABLE — zéro dépendance. Travaille sur { filename, mime, bytes|text }.
// ══════════════════════════════════════════════════════════════

export type UploadThreat =
    | 'dangerous_extension'
    | 'double_extension'
    | 'path_traversal'
    | 'null_byte'
    | 'mime_mismatch'
    | 'script_in_svg'
    | 'embedded_php'
    | 'embedded_script'
    | 'polyglot'

export interface UploadScanVerdict {
    safe: boolean
    threat: UploadThreat | null
    detail: string
}

export interface UploadInput {
    filename: string
    /** MIME déclaré par le client (non fiable — on le confronte). */
    mime?: string
    /** Premiers octets du fichier (pour les magic bytes). */
    bytes?: Uint8Array
    /** Contenu texte (pour SVG/HTML/XML). */
    text?: string
}

// Extensions serveur / exécutables interdites (même en 2e position).
const DANGEROUS_EXT = [
    'php', 'php3', 'php4', 'php5', 'php7', 'phtml', 'phar',
    'jsp', 'jspx', 'asp', 'aspx', 'ashx', 'cgi', 'pl', 'py', 'rb', 'sh', 'bash',
    'exe', 'dll', 'bat', 'cmd', 'com', 'msi', 'jar', 'htaccess',
]

// Signatures (magic bytes) → famille de type réel.
const MAGIC: { sig: number[]; type: string }[] = [
    { sig: [0xFF, 0xD8, 0xFF],        type: 'image/jpeg' },
    { sig: [0x89, 0x50, 0x4E, 0x47],  type: 'image/png' },
    { sig: [0x47, 0x49, 0x46, 0x38],  type: 'image/gif' },
    { sig: [0x25, 0x50, 0x44, 0x46],  type: 'application/pdf' },        // %PDF
    { sig: [0x50, 0x4B, 0x03, 0x04],  type: 'application/zip' },         // PK.. (zip/docx/xlsx)
]

function ext(filename: string): string[] {
    return filename.toLowerCase().split('.').slice(1)
}

function startsWith(bytes: Uint8Array, sig: number[]): boolean {
    if (bytes.length < sig.length) return false
    for (let i = 0; i < sig.length; i++) if (bytes[i] !== sig[i]) return false
    return true
}

function detectRealType(bytes?: Uint8Array): string | null {
    if (!bytes) return null
    for (const m of MAGIC) if (startsWith(bytes, m.sig)) return m.type
    return null
}

const t = (threat: UploadThreat, detail: string): UploadScanVerdict => ({ safe: false, threat, detail })

/** Analyse un upload. Ne lève jamais. */
export function scanUpload(input: UploadInput): UploadScanVerdict {
    const safe: UploadScanVerdict = { safe: true, threat: null, detail: '' }
    const name = (input.filename || '').trim()

    // 1. Null byte / path traversal dans le nom
    if (name.includes('\0') || name.includes('%00')) {
        return t('null_byte', 'Null byte dans le nom de fichier')
    }
    if (/(^|[\\/])\.\.([\\/]|$)/.test(name) || name.startsWith('/') || /^[a-z]:\\/i.test(name)) {
        return t('path_traversal', `Chemin suspect dans le nom : ${name}`)
    }

    const parts = ext(name)

    // 2. Extension dangereuse (à n'importe quelle position → double extension)
    for (let i = 0; i < parts.length; i++) {
        if (DANGEROUS_EXT.includes(parts[i])) {
            if (i < parts.length - 1) {
                return t('double_extension', `Extension exécutable masquée : .${parts[i]} dans "${name}"`)
            }
            return t('dangerous_extension', `Extension exécutable : .${parts[i]}`)
        }
    }

    // 3. Contenu : SVG/HTML/XML avec script
    const text = input.text ?? (input.bytes ? safeText(input.bytes) : '')
    if (text) {
        const low = text.toLowerCase()
        if ((low.includes('<svg') || name.endsWith('.svg')) &&
            /<script|on\w+\s*=|javascript:|<foreignobject|<!entity/i.test(low)) {
            return t('script_in_svg', 'SVG contenant du script/handler (XSS stocké)')
        }
        if (/<\?php|<\?=/.test(low)) {
            return t('embedded_php', 'Code PHP embarqué dans le fichier')
        }
        // Polyglote : magic bytes image mais contenu script serveur/JS exécutable
        const realType = detectRealType(input.bytes)
        if (realType && realType.startsWith('image/') &&
            /<\?php|<script|eval\(|base64_decode\(/i.test(low)) {
            return t('polyglot', `Polyglote : signature ${realType} mais contient du code exécutable`)
        }
    }

    // 4. Incohérence MIME déclaré vs signature réelle
    const realType = detectRealType(input.bytes)
    if (input.mime && realType) {
        const declared = input.mime.toLowerCase()
        // zip couvre docx/xlsx/pptx/odt → toléré
        const zipFamily = declared.includes('officedocument') || declared.includes('opendocument') || declared === 'application/zip'
        if (realType === 'application/zip' && zipFamily) {
            return safe
        }
        if (declared !== realType && !declared.startsWith(realType.split('/')[0] + '/')) {
            return t('mime_mismatch', `MIME déclaré "${declared}" ≠ signature réelle "${realType}"`)
        }
    }

    return safe
}

/** Décode des octets en texte (UTF-8 best-effort, sans throw). */
function safeText(bytes: Uint8Array): string {
    try {
        if (typeof TextDecoder !== 'undefined') {
            return new TextDecoder('utf-8', { fatal: false }).decode(bytes.slice(0, 65536))
        }
    } catch { /* ignore */ }
    let s = ''
    const n = Math.min(bytes.length, 65536)
    for (let i = 0; i < n; i++) s += String.fromCharCode(bytes[i])
    return s
}
