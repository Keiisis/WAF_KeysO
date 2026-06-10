<div align="center">

# 💼 KeysO-WAF — Roadmap commerciale

*Stratégie de monétisation, tarification, packaging & distribution*

</div>

---

## 1. Positionnement produit

KeysO-WAF n'est pas « un énième plugin de sécurité ». Son angle unique :

> **La micro-chirurgie défensive** — détecter non seulement *ce que l'attaquant
> envoie* (payloads), mais aussi *ce qu'il a le droit de toucher* (autorisation objet).

| | WAF classiques (Wordfence, Sucuri…) | **KeysO-WAF** |
|---|---|---|
| Filtrage URL / regex OWASP | ✅ | ✅ |
| Analyse structurelle du **body** (proto pollution, désérialisation) | ❌ | ✅ |
| **Anti-IDOR/BOLA** au niveau objet | ❌ | ✅ (helper natif) |
| Cœur **portable** multi-stack (TS + PHP) | ❌ | ✅ |
| Sans service tiers / sans fuite de données | partiel | ✅ |

**Cible** : agences web, SaaS, e-commerce, développeurs sous Next.js / WordPress /
Laravel qui veulent une sécurité applicative *dans leur code*, pas un proxy externe.

---

## 2. Modèle économique — 3 produits, 1 cœur

Le même `core/` alimente trois lignes de revenus :

### 🅐 SDK développeur (`keyso-waf` sur npm + Packagist)
Pour les devs qui intègrent le WAF dans leur application.

### 🅑 Plugin WordPress (`keyso-waf.zip`)
Pour les 43 % du web sous WordPress — installation en 1 clic.

### 🅒 Licences entreprise & support
Pour les organisations qui veulent SLA, règles custom, audit.

---

## 3. Grille tarifaire

### 🅐 SDK développeur

| Tier | Prix | Inclus |
|------|------|--------|
| **Community** | Gratuit (éval / non-commercial) | Core body-scanner + ownership, 1 adapter |
| **Pro** | **49 €/dev/an** | Tous les adapters, support e-mail, mises à jour |
| **Team** | **199 €/an** (jusqu'à 10 devs) | + règles custom, priorité support |
| **Source** | **990 € one-shot** | Licence source perpétuelle, marque blanche |

### 🅑 Plugin WordPress

| Tier | Prix | Inclus |
|------|------|--------|
| **Free** | 0 € | Body scanner + brute-force + honeypot + dashboard |
| **Pro** | **39 €/site/an** ou **89 €/an** (5 sites) | + anti-IDOR avancé, rate-limit géo, alertes e-mail, règles custom, mises à jour auto |
| **Agency** | **249 €/an** | Sites illimités, marque blanche, support prioritaire |
| **Lifetime** | **399 €** one-shot | Pro à vie, 1 site |

> **Modèle freemium** : la version Free (déjà dans ce repo) acquiert les utilisateurs ;
> le Pro déverrouille les modules avancés. C'est le moteur de croissance organique.

### 🅒 Entreprise

| Offre | Prix indicatif |
|-------|----------------|
| **Support SLA** (réponse < 24 h) | 1 500 €/an |
| **Règles custom + intégration** | sur devis (à partir de 2 000 €) |
| **Audit de sécurité applicatif** | sur devis |

---

## 4. Free vs Pro — la frontière de valeur

| Fonctionnalité | Free | Pro |
|---|:---:|:---:|
| Body scanner (proto pollution / RCE / SSRF / DoS) | ✅ | ✅ |
| Brute-force lockout + rate-limit | ✅ | ✅ |
| Honeypot + security headers | ✅ | ✅ |
| Dashboard + journal (30 j) | ✅ | ✅ |
| **Anti-IDOR auto** (mapping ressources sans code) | — | ✅ |
| **Alertes e-mail / Slack** temps réel | — | ✅ |
| **Géo-blocage + ASN** (datacenters, VPN, Tor) | — | ✅ |
| **Règles personnalisées** (UI) | — | ✅ |
| **Journal étendu** (1 an) + export CSV | — | ✅ |
| **Mises à jour automatiques** signées | — | ✅ |
| **Support** | communauté | prioritaire |

---

## 5. Packaging & distribution

### Plugin WordPress
- **Artefact** : `wordpress-plugin/keyso-waf.zip` (généré par `build-zip.ps1` / `.sh`)
- **Free** → soumis au répertoire **WordPress.org** (acquisition massive, gratuit).
  > ⚠️ WordPress.org exige une licence GPL pour le code hébergé. Stratégie : publier
  > un **cœur Free GPL** sur .org, et vendre le **module Pro** (add-on) hors .org
  > sous licence commerciale (modèle Wordfence / Yoast).
- **Pro** → vendu sur un site dédié + **Freemius** ou **Lemon Squeezy** (gèrent
  paiement, licences, mises à jour auto, TVA). Freemius prend ~7 % mais fait tout.

### SDK npm / Packagist
- `npm publish` (scope `@keyso/waf-core` ou `keyso-waf`)
- Version PHP sur **Packagist** (`composer require keyso/waf`)
- Le `dist/` est buildé via `npm run build` (déjà fonctionnel ✅)

### Licence
- Repo public = **vitrine** (lecture du code, confiance) mais licence propriétaire
  (voir `LICENSE`) → usage commercial payant.
- Alternative : **dual-licensing** (GPL pour open-source, commerciale pour le reste).

---

## 6. Roadmap technique → valeur commerciale

| Étape | Débloque la vente de… | Statut |
|-------|----------------------|--------|
| Core body-scanner + ownership (TS + PHP) | SDK Community + Plugin Free | ✅ Fait |
| Plugin WordPress installable | Plugin Free / Pro | ✅ Fait |
| `npm run build` → dist | Publication npm | ✅ Fait |
| Alertes e-mail / Slack | Plugin Pro | ⬜ |
| Mapping anti-IDOR sans code (UI WP) | Plugin Pro | ⬜ |
| Géo-blocage + threat intel (ASN/VPN/Tor) | Plugin Pro | ⬜ |
| Intégration Freemius (licences + updates) | Tout le Pro | ⬜ |
| Adapters Express / Fastify / Laravel packagés | SDK Pro | ⬜ |
| Détection comportementale portable (scoring, tarpit) | Tier Enterprise | ⬜ |
| Tests + benchmarks + badge sécurité | Crédibilité / closing | ⬜ |

---

## 7. Go-to-market (90 premiers jours)

1. **J0–J30** : publier le plugin **Free** sur WordPress.org + le SDK **Community**
   sur npm. Objectif : premières installs + retours.
2. **J30–J60** : brancher Freemius, sortir le **Pro** (anti-IDOR auto + alertes).
   Contenu : articles « comment j'ai trouvé un IDOR dans X », démos d'attaques bloquées.
3. **J60–J90** : approcher les **agences** (offre Agency marque blanche) + premiers
   contrats **support SLA**. Programme d'affiliation (30 % récurrent).

**Indicateur clé** : taux de conversion Free → Pro (cible 2–4 % à 6 mois).

---

## 8. Atouts différenciants à marketer

- 🧠 *« Le seul WAF WordPress qui bloque la Prototype Pollution et l'IDOR. »*
- 🪶 *« Zéro service tiers, zéro fuite de données, zéro ralentissement. »*
- 🔌 *« Un seul moteur, tous vos sites : WordPress, Next.js, Laravel. »*
- 🛡️ *« Pensé par des défenseurs offensifs : on bloque ce que les autres ne voient pas. »*

---

<div align="center">

*Document stratégique — KeysO. À affiner avec un conseil juridique pour la
structuration des licences (GPL/commerciale) avant publication sur WordPress.org.*

</div>
