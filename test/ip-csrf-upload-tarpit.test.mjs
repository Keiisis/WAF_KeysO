// Tests : client-ip (anti-spoof), CSRF, upload scanner, tarpit borné.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { resolveClientIp, ipMatches } from '../dist/core/client-ip.js'
import { checkOrigin, checkDoubleSubmit, constantTimeEqual } from '../dist/core/csrf.js'
import { scanUpload } from '../dist/core/upload-scanner.js'
import { boundedTarpit, __resetTarpitMetrics, tarpitMetrics } from '../dist/core/tarpit.js'

// ── client-ip ──
test('IP — sans proxy de confiance, on ignore XFF (anti-spoof)', () => {
    const ip = resolveClientIp({
        socketIp: '203.0.113.5',
        headers: { 'x-forwarded-for': '1.2.3.4' }, // tentative de spoof
        trustedProxies: [],
    })
    assert.equal(ip, '203.0.113.5')
})

test('IP — socket non-confiance : XFF ignoré', () => {
    const ip = resolveClientIp({
        socketIp: '203.0.113.5', // pas dans trusted
        headers: { 'x-forwarded-for': '1.2.3.4' },
        trustedProxies: ['10.0.0.0/8'],
    })
    assert.equal(ip, '203.0.113.5')
})

test('IP — socket de confiance : on lit le vrai client dans XFF', () => {
    const ip = resolveClientIp({
        socketIp: '10.0.0.9',
        headers: { 'x-forwarded-for': '88.88.88.88, 10.0.0.9' },
        trustedProxies: ['10.0.0.0/8'],
    })
    assert.equal(ip, '88.88.88.88')
})

test('IP — Cloudflare : CF-Connecting-IP fiable derrière proxy de confiance', () => {
    const ip = resolveClientIp({
        socketIp: '173.245.48.10',
        headers: { 'cf-connecting-ip': '99.99.99.99' },
        trustedProxies: ['173.245.48.0/20'],
    })
    assert.equal(ip, '99.99.99.99')
})

test('IP — ipMatches CIDR', () => {
    assert.equal(ipMatches('10.5.6.7', '10.0.0.0/8'), true)
    assert.equal(ipMatches('11.5.6.7', '10.0.0.0/8'), false)
    assert.equal(ipMatches('192.168.1.1', '192.168.1.1'), true)
})

// ── CSRF ──
test('CSRF — GET est sûr', () => {
    assert.equal(checkOrigin('GET', null, null, ['ex.com']).valid, true)
})

test('CSRF — POST sans origin ni referer = refus', () => {
    assert.equal(checkOrigin('POST', null, null, ['ex.com']).valid, false)
})

test('CSRF — origin autorisé / refusé', () => {
    assert.equal(checkOrigin('POST', 'https://ex.com', null, ['ex.com']).valid, true)
    assert.equal(checkOrigin('POST', 'https://evil.com', null, ['ex.com']).valid, false)
})

test('CSRF — double submit', () => {
    const tok = 'a'.repeat(32)
    assert.equal(checkDoubleSubmit(tok, tok).valid, true)
    assert.equal(checkDoubleSubmit(tok, 'b'.repeat(32)).valid, false)
    assert.equal(checkDoubleSubmit('short', 'short').valid, false) // trop court
})

test('CSRF — comparaison temps constant', () => {
    assert.equal(constantTimeEqual('abc', 'abc'), true)
    assert.equal(constantTimeEqual('abc', 'abd'), false)
    assert.equal(constantTimeEqual('abc', 'ab'), false)
})

// ── Upload scanner ──
test('upload — image légitime OK', () => {
    const v = scanUpload({ filename: 'photo.jpg', mime: 'image/jpeg', bytes: new Uint8Array([0xFF, 0xD8, 0xFF, 0xE0]) })
    assert.equal(v.safe, true)
})

test('upload — double extension shell.php.jpg', () => {
    const v = scanUpload({ filename: 'shell.php.jpg' })
    assert.equal(v.safe, false)
    assert.equal(v.threat, 'double_extension')
})

test('upload — extension exécutable', () => {
    assert.equal(scanUpload({ filename: 'x.php' }).threat, 'dangerous_extension')
})

test('upload — path traversal dans le nom', () => {
    assert.equal(scanUpload({ filename: '../../etc/passwd' }).threat, 'path_traversal')
})

test('upload — SVG avec script', () => {
    const v = scanUpload({ filename: 'logo.svg', text: '<svg onload="alert(1)"><script>evil()</script></svg>' })
    assert.equal(v.safe, false)
    assert.equal(v.threat, 'script_in_svg')
})

test('upload — PHP embarqué', () => {
    const v = scanUpload({ filename: 'note.txt', text: 'hello <?php system($_GET[c]); ?>' })
    assert.equal(v.threat, 'embedded_php')
})

test('upload — polyglote (magic JPEG + PHP)', () => {
    const text = '\xFF\xD8\xFF hidden <?php eval($_POST[x]); ?>'
    const bytes = new Uint8Array([0xFF, 0xD8, 0xFF, ...[...'hidden <?php eval($_POST[x]); ?>'].map(c => c.charCodeAt(0))])
    const v = scanUpload({ filename: 'image.jpg', bytes, text })
    assert.equal(v.safe, false)
})

test('upload — MIME mismatch (déclaré png, signature pdf)', () => {
    const v = scanUpload({ filename: 'f.png', mime: 'image/png', bytes: new Uint8Array([0x25, 0x50, 0x44, 0x46]) })
    assert.equal(v.safe, false)
    assert.equal(v.threat, 'mime_mismatch')
})

// ── Tarpit borné ──
test('tarpit — applique un délai sous le plafond', async () => {
    __resetTarpitMetrics()
    const r = await boundedTarpit(50, { maxConcurrent: 5 })
    assert.equal(r.applied, true)
    assert.equal(r.delayMs, 50)
})

test('tarpit — plafond de concurrence respecté (anti auto-DoS)', async () => {
    __resetTarpitMetrics()
    // Lancer plus de tarpits que le plafond ; les excédentaires sont skippés.
    const cap = 3
    const promises = Array.from({ length: 10 }, () => boundedTarpit(200, { maxConcurrent: cap }))
    const results = await Promise.all(promises)
    const applied = results.filter(r => r.applied).length
    const skipped = results.filter(r => r.skippedReason === 'cap_reached').length
    assert.ok(applied <= cap, `applied (${applied}) ne doit pas dépasser le plafond (${cap})`)
    assert.ok(skipped >= 10 - cap, 'les excédentaires doivent être skippés')
})

test('tarpit — délai 0 non appliqué', async () => {
    const r = await boundedTarpit(0)
    assert.equal(r.applied, false)
    assert.equal(r.skippedReason, 'zero_delay')
})
