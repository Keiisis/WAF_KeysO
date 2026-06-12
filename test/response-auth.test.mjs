// Tests : response-inspector (data leakage) + auth-anomaly (stuffing/travel).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { inspectResponse } from '../dist/core/response-inspector.js'
import {
    detectCredentialStuffing, detectImpossibleTravel, haversineKm,
} from '../dist/core/auth-anomaly.js'

// ── response-inspector ──
test('réponse propre = sûre', () => {
    assert.equal(inspectResponse('{"ok":true,"user":"Jean"}').safe, true)
})

test('détecte une clé Stripe live', () => {
    const v = inspectResponse('{"key":"sk_live_abcdefABCDEF1234567890"}')
    assert.equal(v.safe, false)
    assert.ok(v.leaks.some(l => l.type === 'secret_key'))
})

test('détecte une clé privée PEM', () => {
    const v = inspectResponse('-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----')
    assert.ok(v.leaks.some(l => l.type === 'private_key'))
    assert.equal(v.highestSeverity, 4)
})

test('détecte une stack trace', () => {
    const v = inspectResponse('Error\n    at handler (/var/www/app/index.js:42:13)')
    assert.ok(v.leaks.some(l => l.type === 'stack_trace'))
})

test('détecte une erreur SQL brute', () => {
    const v = inspectResponse("SQLSTATE[42000]: Syntax error near 'WHERE'")
    assert.ok(v.leaks.some(l => l.type === 'sql_error'))
})

test('détecte une carte bancaire valide (Luhn)', () => {
    const v = inspectResponse('paiement 4111 1111 1111 1111 accepté') // test Visa, Luhn-valide
    assert.ok(v.leaks.some(l => l.type === 'credit_card'))
})

test('ignore un faux numéro (Luhn invalide)', () => {
    const v = inspectResponse('ref 1234 5678 9012 3456 9999') // pas Luhn-valide
    assert.ok(!v.leaks.some(l => l.type === 'credit_card'))
})

test('redaction masque les secrets', () => {
    const v = inspectResponse('token sk_live_abcdefABCDEF1234567890 ok', { redact: true })
    assert.ok(v.redacted.includes('«secret masqué»'))
    assert.ok(!v.redacted.includes('sk_live_'))
})

test('détecte un dump massif d\'emails', () => {
    let body = ''
    for (let i = 0; i < 30; i++) body += `user${i}@example.com\n`
    const v = inspectResponse(body)
    assert.ok(v.leaks.some(l => l.type === 'pii_email_bulk'))
})

// ── credential-stuffing ──
test('password spray : 1 IP, beaucoup d\'users', () => {
    const now = Date.now()
    const attempts = []
    for (let i = 0; i < 12; i++) attempts.push({ ip: '1.2.3.4', username: `user${i}`, success: false, at: now })
    const v = detectCredentialStuffing(attempts, { ip: '1.2.3.4' })
    assert.equal(v.suspicious, true)
    assert.equal(v.pattern, 'password_spray')
})

test('stuffing distribué : 1 compte, beaucoup d\'IP', () => {
    const now = Date.now()
    const attempts = []
    for (let i = 0; i < 7; i++) attempts.push({ ip: `10.0.0.${i}`, username: 'victim', success: false, at: now })
    const v = detectCredentialStuffing(attempts, { username: 'victim' })
    assert.equal(v.suspicious, true)
    assert.equal(v.pattern, 'distributed_stuffing')
})

test('trafic login normal = non suspect', () => {
    const now = Date.now()
    const attempts = [
        { ip: '1.2.3.4', username: 'alice', success: true, at: now },
        { ip: '1.2.3.4', username: 'alice', success: false, at: now },
    ]
    assert.equal(detectCredentialStuffing(attempts, { ip: '1.2.3.4' }).suspicious, false)
})

test('fenêtre temporelle : anciens attempts ignorés', () => {
    const old = Date.now() - 60 * 60_000 // 1h
    const attempts = []
    for (let i = 0; i < 12; i++) attempts.push({ ip: '1.2.3.4', username: `u${i}`, success: false, at: old })
    assert.equal(detectCredentialStuffing(attempts, { ip: '1.2.3.4' }, { windowMs: 10 * 60_000 }).suspicious, false)
})

// ── impossible travel ──
test('haversine Paris→New York ≈ 5837 km', () => {
    const d = haversineKm({ lat: 48.85, lon: 2.35 }, { lat: 40.71, lon: -74.0 })
    assert.ok(d > 5700 && d < 6000, `distance=${d}`)
})

test('impossible travel : Paris→NY en 1h', () => {
    const t0 = Date.now()
    const v = detectImpossibleTravel(
        { lat: 48.85, lon: 2.35, at: t0 },
        { lat: 40.71, lon: -74.0, at: t0 + 3_600_000 },
    )
    assert.equal(v.impossible, true)
})

test('déplacement plausible : Paris→NY en 9h (avion)', () => {
    const t0 = Date.now()
    const v = detectImpossibleTravel(
        { lat: 48.85, lon: 2.35, at: t0 },
        { lat: 40.71, lon: -74.0, at: t0 + 9 * 3_600_000 },
    )
    assert.equal(v.impossible, false)
})

test('distance intra-urbaine ignorée', () => {
    const t0 = Date.now()
    const v = detectImpossibleTravel(
        { lat: 48.85, lon: 2.35, at: t0 },
        { lat: 48.86, lon: 2.36, at: t0 + 60_000 },
    )
    assert.equal(v.impossible, false)
})
