// ──────────────────────────────────────────────────────────────
// Exemple : Express + Prisma — scanBody + verifyOwnership
// ──────────────────────────────────────────────────────────────
// npm i express keyso-waf
//
// Montre l'usage du CORE pur (sans l'adapter Next.js) dans Express.
// ──────────────────────────────────────────────────────────────

import express, { Request, Response, NextFunction } from 'express'
import { scanBody, verifyOwnership, type OwnershipResolver } from 'keyso-waf'

const app = express()
app.use(express.json({ limit: '1mb' }))

// ── Middleware #2 : analyse structurelle de tous les bodies JSON ──
app.use((req: Request, res: Response, next: NextFunction) => {
    if (req.body && typeof req.body === 'object') {
        const verdict = scanBody(req.body)
        if (!verdict.safe) {
            console.warn(`[WAF] ${verdict.threat} @ ${verdict.path} — ${verdict.detail}`)
            return res.status(400).json({ error: 'Requête invalide.' })
        }
    }
    next()
})

// ── Resolver d'ownership (ex. Prisma) ──
// Remplacez par votre couche d'accès données.
const resolver: OwnershipResolver = async ({ resourceType, resourceId }) => {
    if (resourceType === 'invoice') {
        // const inv = await prisma.invoice.findUnique({ where: { id: resourceId } })
        const inv = { userId: 'owner-123' } as { userId: string } | null // demo
        return { ownerId: inv?.userId ?? null, notFound: !inv }
    }
    return { ownerId: null, notFound: true }
}

// ── Route protégée #1 : autorisation au niveau objet ──
app.get('/api/invoices/:id', async (req: Request, res: Response) => {
    const userId = (req as Request & { userId?: string }).userId || '' // depuis votre auth
    const verdict = await verifyOwnership(resolver, {
        userId,
        resourceType: 'invoice',
        resourceId: req.params.id,
    })
    if (!verdict.allowed) {
        // 404 plutôt que 403 → ne révèle pas l'existence de la ressource
        return res.status(404).json({ error: 'Ressource introuvable.' })
    }
    res.json({ ok: true, invoice: req.params.id })
})

app.listen(3000, () => console.log('KeysO-WAF demo on :3000'))
