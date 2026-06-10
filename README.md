<div align="center">

# 🛡️ KeysO-WAF

### Le WAF-SDK portable, conçu pour devenir incontournable.

**Analyse structurelle de payload** (Prototype Pollution · RCE · SSRF · DoS)
**+ Autorisation au niveau objet** (anti-IDOR / BOLA réel)

*Un core pur, zéro dépendance, réutilisable pour bâtir des plugins de sécurité*
*Next.js · Express · WordPress · PHP · et au-delà.*

</div>

---

## 🎯 Pourquoi KeysO-WAF ?

Les WAF classiques regardent l'**URL** et appliquent des regex OWASP. Ils ratent deux
classes d'attaques modernes parmi les plus dévastatrices :

1. **Ce que l'attaquant met dans le _corps_ de la requête** — prototype pollution,
   gadgets de désérialisation (RCE), SSRF cachés dans des valeurs JSON. L'URL est propre,
   le payload est mortel.
2. **Ce à quoi l'attaquant a le _droit_ de toucher** — l'IDOR/BOLA (#1 de l'OWASP API
   Security). Un utilisateur légitime (token valide) lit la facture d'un autre en
   changeant un `id`. Aucune regex ne le détecte.

KeysO-WAF couvre **exactement ces deux angles morts**, avec une architecture pensée pour
être **extraite, portée et commercialisée** sur n'importe quelle stack.

---

## 🧱 Architecture : Core pur + Adapters jetables

```
keyso-waf/
├── src/
│   ├── core/                  ← LE PRODUIT. Zéro dépendance framework/DB.
│   │   ├── body-scanner.ts        #2 — analyse structurelle (pure)
│   │   └── ownership.ts           #1 — autorisation objet (datastore injecté)
│   └── adapters/              ← Couche de COLLE, réécrite par plateforme.
│       ├── nextjs.ts              lecture body + réponses Next.js
│       └── supabase-ownership.ts  resolver de propriété Postgres/Supabase
├── php/                       ← Port PHP du core (plugins WordPress/PHP)
│   ├── BodyScanner.php
│   └── Ownership.php
└── examples/                  ← Express + WordPress prêts à copier
```

**Règle d'or** : `core/` n'importe **jamais** un framework ou une base de données.
Toute I/O passe par une fonction injectée. C'est ce qui rend le produit portable et
incontournable : on garde le cerveau, on remplace seulement les bras.

---

## ⚡ Installation

```bash
npm install keyso-waf
# peerDependencies optionnelles selon l'adapter utilisé :
#   next  (adapter Next.js)   ·   @supabase/supabase-js (resolver Supabase)
```

Pour PHP/WordPress : copiez simplement `php/BodyScanner.php` et `php/Ownership.php`.

---

## 🛡️ Protection #2 — `scanBody` (analyse structurelle)

Détecte ce qui ne passe pas par l'URL :

| Catégorie | Exemples détectés |
|-----------|-------------------|
| **Prototype Pollution** | clés `__proto__`, `constructor`, `prototype` |
| **RCE / désérialisation** | `child_process`, `require(`, `eval(`, gadget `node-serialize`, SSTI, PHP object injection `O:N:"..."` |
| **SSRF dans les valeurs** | IP internes (parsing d'octets **correct**, pas de match substring naïf), cloud metadata `169.254.169.254`, schémas `gopher://`/`file://` |
| **DoS structurel** | profondeur récursive, explosion de clés/tableaux, strings géantes |

```ts
import { scanBody } from 'keyso-waf'

const verdict = scanBody(JSON.parse(rawBody))
if (!verdict.safe) {
  // verdict.threat : 'prototype_pollution' | 'rce_gadget' | 'ssrf_internal_target' | ...
  // verdict.path   : "user.profile.__proto__"   (où la menace a été trouvée)
  return block(400)
}
```

> 🔒 **Parsing d'IP correct** : `10.0.0.5` est interne, mais `"version 10.2"` ne l'est
> pas. KeysO-WAF parse les 4 octets — fini les faux positifs des blacklists naïves
> `includes('10.')`. `172.16–172.31` est privé, `172.0–172.15` ne l'est pas : on le sait.

---

## 🔐 Protection #1 — `verifyOwnership` (anti-IDOR / BOLA réel)

Répond à : **« cet utilisateur a-t-il le droit de toucher CETTE ressource ? »**

La plupart des "protections IDOR" détectent l'**énumération** (balayage de 1,2,3,4…).
C'est insuffisant : un accès **ciblé unique** (user 42 lit la facture de user 1, une
seule fois) passe à travers. KeysO-WAF vérifie la **propriété réelle**.

```ts
import { verifyOwnership, type OwnershipResolver } from 'keyso-waf'

// Le resolver est injecté → c'est la SEULE pièce à réécrire par plateforme.
const resolver: OwnershipResolver = async ({ resourceType, resourceId }) => {
  const inv = await db.invoice.find(resourceId)
  return { ownerId: inv?.userId ?? null, notFound: !inv }
}

const verdict = await verifyOwnership(resolver, {
  userId, resourceType: 'invoice', resourceId: '42',
})
if (!verdict.allowed) return block() // decision: 'foreign' | 'not_found_denied'
```

- **Fail-closed** : erreur resolver → accès refusé (pas de fuite).
- **Staff override** optionnel (admin/agent transverse).
- **`missingPolicy`** `'deny'` (défaut, recommandé) ou `'allow'`.

---

## 🚀 Démarrage rapide — Next.js (App Router)

```ts
// app/api/invoices/[id]/route.ts
import {
  scanRequestBody,
  assertOwnership,
  createSupabaseOwnershipResolver,
} from 'keyso-waf'

const resolver = createSupabaseOwnershipResolver(supabase, {
  invoice: { table: 'invoices', ownerColumn: 'user_id' },
})

export async function POST(req: Request) {
  // #2 — body scan (réutilise le body parsé, pas de double req.json())
  const { body, rejection } = await scanRequestBody(req)
  if (rejection) return rejection

  // #1 — autorisation objet (404 'deceive' = ne révèle pas l'existence)
  const { rejection: idor } = await assertOwnership({
    userId, resourceType: 'invoice', resourceId: id, resolver,
    rejectMode: 'deceive',
  })
  if (idor) return idor

  // ... logique métier avec `body`
}
```

## 🐘 Démarrage rapide — WordPress / PHP

```php
require_once __DIR__ . '/BodyScanner.php';
require_once __DIR__ . '/Ownership.php';
use WafCore\BodyScanner;
use WafCore\Ownership;

// #2 — bloque proto-pollution/RCE/SSRF sur toutes les requêtes REST
add_filter('rest_pre_dispatch', function ($result, $server, $request) {
    $verdict = BodyScanner::scan($request->get_json_params() ?: []);
    if (!$verdict['safe']) return new WP_Error('waf', 'Requête invalide.', ['status' => 400]);
    return $result;
}, 10, 3);
```

Exemple complet : [`examples/wordpress-plugin.php`](examples/wordpress-plugin.php).

---

## 🌍 Matrice de portage

| Plateforme | Ce qu'on garde | Ce qu'on (ré)écrit |
|------------|----------------|--------------------|
| **Next.js + Supabase** | `src/core/` | `adapters/nextjs.ts`, `adapters/supabase-ownership.ts` (fournis) |
| **Express + Prisma** | `src/core/` (tel quel) | un resolver Prisma + middleware ([`examples/express.ts`](examples/express.ts)) |
| **WordPress** | `php/` (fourni) | resolver `wpdb` + hook `rest_pre_dispatch` ([`examples/`](examples/wordpress-plugin.php)) |
| **PHP / Laravel** | `php/` (fourni) | resolver PDO/Eloquent + middleware |

Le **cerveau** (règles, parsing, logique de décision) ne change jamais. Seuls les
**bras** (accès données, format de réponse) sont spécifiques.

---

## ✅ Garanties

- **Ne lève jamais** — chaque fonction renvoie un verdict, jamais d'exception.
- **Fail-closed** sur l'ownership — une panne du resolver refuse l'accès, ne fuit pas.
- **Zéro état global** dans le core — `scanBody`/`verifyOwnership` sont des fonctions pures.
- **Zéro dépendance runtime** dans `src/core/` — seuls les `adapters/` importent un framework.
- **Parsing d'IP rigoureux** — pas de faux positifs sur les blacklists substring.

---

## 🗺️ Roadmap

- [ ] Adapters Express & Fastify packagés (au-delà des exemples)
- [ ] Resolver Prisma / Drizzle prêts à l'emploi
- [ ] Détection comportementale (rate-limit adaptatif, scoring de confiance) portable
- [ ] Tarpit & cyber-déception en module portable
- [ ] Plugin WordPress packagé (zip installable)
- [ ] Tests unitaires + benchmarks

---

## 📦 Build

```bash
npm install
npm run build      # → dist/ (ESM + types)
npm run typecheck
```

---

## 📄 Licence

Propriétaire — voir [LICENSE](LICENSE). Usage commercial sous licence écrite KeysO.

<div align="center">

**KeysO-WAF** — *micro-chirurgie défensive : ce que l'attaquant envoie, et ce qu'il a le droit de toucher.*

</div>
