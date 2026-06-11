// Tests ownership + RLS engine.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { verifyOwnership } from '../dist/core/ownership.js'
import {
    evaluateAccess, filterReadable, assertWritable,
    owner, eq, and, or, TRUE, ref,
} from '../dist/core/rls.js'

// ── ownership ──
const resolver = async ({ resourceId }) => {
    const db = { '1': 'alice', '2': 'bob' }
    return { ownerId: db[resourceId] ?? null, notFound: !(resourceId in db) }
}

test('ownership — propriétaire autorisé', async () => {
    const v = await verifyOwnership(resolver, { userId: 'alice', resourceType: 'invoice', resourceId: '1' })
    assert.equal(v.allowed, true)
    assert.equal(v.decision, 'owner')
})

test('ownership — IDOR refusé', async () => {
    const v = await verifyOwnership(resolver, { userId: 'alice', resourceType: 'invoice', resourceId: '2' })
    assert.equal(v.allowed, false)
    assert.equal(v.decision, 'foreign')
})

test('ownership — introuvable fail-closed (deny par défaut)', async () => {
    const v = await verifyOwnership(resolver, { userId: 'alice', resourceType: 'invoice', resourceId: '999' })
    assert.equal(v.allowed, false)
    assert.equal(v.decision, 'not_found_denied')
})

test('ownership — resolver qui throw → refus (fail-closed)', async () => {
    const bad = async () => { throw new Error('db down') }
    const v = await verifyOwnership(bad, { userId: 'alice', resourceType: 'x', resourceId: '1' })
    assert.equal(v.allowed, false)
})

test('ownership — staff override', async () => {
    const v = await verifyOwnership(resolver,
        { userId: 'admin', resourceType: 'invoice', resourceId: '2' },
        { isStaff: () => true })
    assert.equal(v.allowed, true)
    assert.equal(v.decision, 'staff_override')
})

// ── RLS engine ──
const policies = [
    { name: 'own_select', table: 'invoices', action: 'select', using: owner('user_id') },
    { name: 'staff_all', table: 'invoices', action: '*', role: 'admin', using: TRUE },
    { name: 'insert_self', table: 'invoices', action: 'insert', check: eq('user_id', ref('auth.uid')) },
]

test('RLS — owner voit sa ligne', () => {
    const v = evaluateAccess(policies, {
        table: 'invoices', action: 'select',
        auth: { uid: 'u1', role: 'client' },
        row: { id: 1, user_id: 'u1' },
    })
    assert.equal(v.allowed, true)
    assert.equal(v.matchedPolicy, 'own_select')
})

test('RLS — owner ne voit pas la ligne d\'autrui (default deny)', () => {
    const v = evaluateAccess(policies, {
        table: 'invoices', action: 'select',
        auth: { uid: 'u1', role: 'client' },
        row: { id: 2, user_id: 'u2' },
    })
    assert.equal(v.allowed, false)
})

test('RLS — admin voit tout (rôle + wildcard action)', () => {
    const v = evaluateAccess(policies, {
        table: 'invoices', action: 'select',
        auth: { uid: 'admin1', role: 'admin' },
        row: { id: 2, user_id: 'u2' },
    })
    assert.equal(v.allowed, true)
    assert.equal(v.matchedPolicy, 'staff_all')
})

test('RLS — insert : check user_id == auth.uid', () => {
    const ok = evaluateAccess(policies, {
        table: 'invoices', action: 'insert',
        auth: { uid: 'u1', role: 'client' }, row: { user_id: 'u1' },
    })
    const ko = evaluateAccess(policies, {
        table: 'invoices', action: 'insert',
        auth: { uid: 'u1', role: 'client' }, row: { user_id: 'u2' },
    })
    assert.equal(ok.allowed, true)
    assert.equal(ko.allowed, false)
})

test('RLS — table sans policy = default deny', () => {
    const v = evaluateAccess(policies, {
        table: 'secrets', action: 'select',
        auth: { uid: 'u1', role: 'admin' }, row: {},
    })
    assert.equal(v.allowed, false)
})

test('RLS — filterReadable masque les lignes non autorisées', () => {
    const rows = [{ id: 1, user_id: 'u1' }, { id: 2, user_id: 'u2' }, { id: 3, user_id: 'u1' }]
    const visible = filterReadable(policies, { table: 'invoices', action: 'select', auth: { uid: 'u1', role: 'client' } }, rows)
    assert.deepEqual(visible.map(r => r.id), [1, 3])
})

test('RLS — and/or composés', () => {
    const pol = [{
        name: 'complex', table: 't', action: 'select',
        using: or(owner('owner'), and(eq('public', true), eq('status', 'active'))),
    }]
    const auth = { uid: 'x', role: 'r' }
    assert.equal(evaluateAccess(pol, { table: 't', action: 'select', auth, row: { owner: 'x' } }).allowed, true)
    assert.equal(evaluateAccess(pol, { table: 't', action: 'select', auth, row: { owner: 'y', public: true, status: 'active' } }).allowed, true)
    assert.equal(evaluateAccess(pol, { table: 't', action: 'select', auth, row: { owner: 'y', public: true, status: 'archived' } }).allowed, false)
})

test('RLS — assertWritable détecte la 1re ligne refusée', () => {
    const r = assertWritable(policies, { table: 'invoices', action: 'insert', auth: { uid: 'u1', role: 'client' } },
        [{ user_id: 'u1' }, { user_id: 'u2' }])
    assert.equal(r.ok, false)
    assert.equal(r.rejectedIndex, 1)
})
