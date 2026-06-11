// Tests body-scanner — corpus d'évasion + payloads type-CVE
// node:test (zéro dépendance) contre le build dist/.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { scanBody, isInternalHost } from '../dist/core/body-scanner.js'

test('payload propre est sûr', () => {
    const v = scanBody({ name: 'Jean', age: 30, tags: ['a', 'b'] })
    assert.equal(v.safe, true)
})

test('prototype pollution — __proto__ (via JSON.parse, vecteur réel)', () => {
    // En littéral JS, { '__proto__': x } DÉFINIT le prototype (pas une clé propre).
    // Le vrai payload arrive par JSON.parse qui, lui, crée une clé propre __proto__.
    const v = scanBody(JSON.parse('{"user":{"__proto__":{"isAdmin":true}}}'))
    assert.equal(v.safe, false)
    assert.equal(v.threat, 'prototype_pollution')
})

test('prototype pollution — constructor imbriqué', () => {
    const v = scanBody(JSON.parse('{"a":{"b":{"constructor":{"x":1}}}}'))
    assert.equal(v.safe, false)
    assert.equal(v.threat, 'prototype_pollution')
})

test('RCE — child_process', () => {
    const v = scanBody({ cmd: "require('child_process').exec('id')" })
    assert.equal(v.safe, false)
    assert.equal(v.threat, 'rce_gadget')
})

test('RCE — node-serialize gadget', () => {
    const v = scanBody({ rce: '_$$ND_FUNC$$_function(){return 1}' })
    assert.equal(v.safe, false)
    assert.equal(v.threat, 'rce_gadget')
})

test('SSRF — AWS metadata', () => {
    const v = scanBody({ url: 'http://169.254.169.254/latest/meta-data/' })
    assert.equal(v.safe, false)
    assert.equal(v.threat, 'ssrf_internal_target')
})

test('SSRF — schéma gopher', () => {
    const v = scanBody({ url: 'gopher://127.0.0.1:6379/_INFO' })
    assert.equal(v.safe, false)
    assert.equal(v.threat, 'ssrf_internal_target')
})

test('SSRF — faux positif évité : "version 10.2"', () => {
    const v = scanBody({ note: 'mise à jour version 10.2 disponible' })
    assert.equal(v.safe, true, 'ne doit PAS matcher 10. comme IP interne')
})

test('SSRF — faux positif évité : prix 127.0 €', () => {
    const v = scanBody({ price: 'le total est 127.0 EUR' })
    assert.equal(v.safe, true)
})

test('DoS — profondeur excessive', () => {
    let deep = { v: 1 }
    for (let i = 0; i < 60; i++) deep = { nested: deep }
    const v = scanBody(deep, { maxDepth: 24 })
    assert.equal(v.safe, false)
    assert.equal(v.threat, 'recursive_depth')
})

test('DoS — explosion de clés', () => {
    const big = {}
    for (let i = 0; i < 6000; i++) big['k' + i] = i
    const v = scanBody(big, { maxKeys: 5000 })
    assert.equal(v.safe, false)
    assert.equal(v.threat, 'key_explosion')
})

// ── isInternalHost : plages privées vs publiques ──
test('isInternalHost — plages privées', () => {
    for (const ip of ['127.0.0.1', '10.1.2.3', '192.168.1.1', '172.16.0.1', '172.31.255.255', '169.254.169.254', 'localhost', '::1']) {
        assert.equal(isInternalHost(ip), true, `${ip} doit être interne`)
    }
})

test('isInternalHost — plages publiques', () => {
    for (const ip of ['8.8.8.8', '1.1.1.1', '172.15.0.1', '172.32.0.1', '93.184.216.34', 'example.com']) {
        assert.equal(isInternalHost(ip), false, `${ip} doit être public`)
    }
})
