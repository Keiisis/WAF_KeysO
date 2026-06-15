// Tests du store partagé (MemoryKv) + rate-limit + block-store distribués.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
    MemoryKv, rateLimit, blockIdentity, isBlocked, recordViolation,
} from '../dist/core/kv.js'

test('MemoryKv — incr + ttl', async () => {
    const kv = new MemoryKv()
    assert.equal(await kv.incr('k', 60), 1)
    assert.equal(await kv.incr('k', 60), 2)
    assert.equal(await kv.get('k'), 2)
})

test('MemoryKv — expiration', async () => {
    const kv = new MemoryKv()
    await kv.set('e', 5, 0) // ttl 0s → expire immédiatement
    await new Promise(r => setTimeout(r, 5))
    assert.equal(await kv.get('e'), null)
})

test('rateLimit — fenêtre fixe', async () => {
    const kv = new MemoryKv()
    let last
    for (let i = 0; i < 5; i++) last = await rateLimit(kv, 'ip1', 3, 60)
    // 5 requêtes, max 3 → la 4e+ sont refusées
    assert.equal(last.allowed, false)
    assert.equal(last.count, 5)
    assert.equal(last.remaining, 0)
})

test('rateLimit — sous le seuil = autorisé', async () => {
    const kv = new MemoryKv()
    const r = await rateLimit(kv, 'ip2', 10, 60)
    assert.equal(r.allowed, true)
    assert.equal(r.remaining, 9)
})

test('block-store — block + isBlocked', async () => {
    const kv = new MemoryKv()
    assert.equal(await isBlocked(kv, 'badip'), false)
    await blockIdentity(kv, 'badip', 60)
    assert.equal(await isBlocked(kv, 'badip'), true)
})

test('recordViolation — bloque au seuil', async () => {
    const kv = new MemoryKv()
    let res
    for (let i = 0; i < 5; i++) res = await recordViolation(kv, 'attacker', { threshold: 5, blockTtlSeconds: 60 })
    assert.equal(res.blocked, true)
    assert.equal(res.count, 5)
    assert.equal(await isBlocked(kv, 'attacker'), true)
})

test('recordViolation — sous le seuil = pas de blocage', async () => {
    const kv = new MemoryKv()
    const res = await recordViolation(kv, 'maybe', { threshold: 5 })
    assert.equal(res.blocked, false)
    assert.equal(await isBlocked(kv, 'maybe'), false)
})

test('MemoryKv — cap d\'entrées (anti-fuite mémoire)', async () => {
    const kv = new MemoryKv(100)
    for (let i = 0; i < 250; i++) await kv.set('k' + i, i, 60)
    // le cap doit avoir contenu la taille (≈ maxEntries, pas 250)
    let present = 0
    for (let i = 0; i < 250; i++) if (await kv.get('k' + i) !== null) present++
    assert.ok(present <= 110, `entrées présentes=${present} doit rester proche du cap 100`)
})
