=== KeysO-WAF — Pare-feu applicatif surpuissant ===
Contributors: keyso
Tags: security, firewall, waf, brute-force, idor, ssrf, rce, hardening
Requires at least: 5.8
Tested up to: 6.7
Requires PHP: 8.0
Stable tag: 1.5.0
License: Proprietary (commercial)

WAF nouvelle génération : analyse structurelle des payloads, anti-IDOR, brute-force, rate-limiting, honeypot et journal de sécurité. Léger, sans dépendance.

== Description ==

KeysO-WAF protège votre site WordPress contre des attaques que les pare-feu
classiques ratent, car il ne se contente pas de filtrer l'URL : il analyse la
**structure** des requêtes et vérifie les **droits d'accès aux objets**.

**Ce que KeysO-WAF bloque :**

* **Prototype Pollution** — clés `__proto__`, `constructor`, `prototype`
* **RCE / désérialisation** — `system`, `exec`, `eval`, gadgets PHP object
  injection (`O:N:"..."`), gadgets Node
* **SSRF** — IP internes (parsing d'octets rigoureux), endpoints cloud metadata
  (`169.254.169.254`), schémas `gopher://` / `file://`
* **DoS structurel** — profondeur d'imbrication, explosion de clés/tableaux
* **IDOR / BOLA** — helper d'autorisation au niveau objet pour vos endpoints
* **Brute-force login** — lockout automatique après N tentatives
* **Flood** — rate-limiting par IP
* **Scanners** — chemins pièges (honeypot), path traversal

**Tableau de bord** : statistiques des menaces (30 j) + journal des derniers
événements, directement dans l'admin WordPress.

**Léger & autonome** : aucune dépendance externe, aucun service tiers, aucune
fuite de données. Le moteur d'analyse est un cœur portable réutilisable.

== Installation ==

1. Téléversez le dossier `keyso-waf` dans `/wp-content/plugins/` (ou installez le .zip via Extensions > Ajouter).
2. Activez l'extension via le menu « Extensions ».
3. Rendez-vous dans « KeysO-WAF > Réglages » pour ajuster la protection.

== Usage développeur (anti-IDOR) ==

Dans vos endpoints REST custom :

`
$resolver = function (array $q): array {
    global $wpdb;
    $owner = $wpdb->get_var($wpdb->prepare(
        "SELECT post_author FROM {$wpdb->posts} WHERE ID = %d", $q['resourceId']
    ));
    return ['ownerId' => $owner, 'notFound' => $owner === null];
};

if (!KeysO_WAF\Guard::assertOwnership($resolver, (string) get_current_user_id(), 'post', $id)) {
    return new WP_Error('forbidden', 'Accès refusé.', ['status' => 403]);
}
`

== Frequently Asked Questions ==

= Le plugin ralentit-il mon site ? =
Non. L'analyse est en mémoire, sans appel réseau. Le rate-limiting utilise
l'object cache si disponible.

= Compatible avec un reverse-proxy / Cloudflare ? =
Oui. Par défaut, l'IP est lue depuis `REMOTE_ADDR` (non falsifiable). Si votre
site est derrière un proxy/CDN, sélectionnez l'en-tête correspondant
(`CF-Connecting-IP`, `X-Real-IP`, `X-Forwarded-For`…) dans Réglages → Réseau & IP.
⚠️ Ne l'activez QUE si vous êtes réellement derrière ce proxy : sinon un
attaquant pourrait usurper son IP et contourner les protections.

== Changelog ==

= 1.5.0 =
* Activation par CLÉ DE LICENCE (anti-piratage) : page Licence, vérification
  contre un serveur configurable (KEYSO_WAF_LICENSE_API), revalidation
  quotidienne tolérante aux pannes. Modèle éthique : la protection cœur reste
  TOUJOURS active ; seules les fonctions premium (alertes, anti-IDOR no-code)
  sont réservées aux licences valides.
* Liste NOIRE d'IP (blocage immédiat 403) + message de blocage personnalisable.
* Analyse des POST de formulaires front classiques (hors REST).
* Export CSV du journal de sécurité depuis le tableau de bord.
* Rate-limiting : incrément ATOMIQUE via object cache (Redis/Memcached) si
  présent — élimine la condition de course sous forte charge.
* Internationalisation : fichier de traduction `languages/keyso-waf.pot`.
* Path traversal renforcé : détection sur l'URI COMPLÈTE (path + query string)
  et formes encodées (double-décodage %2e%2e / %252e), attrapant les LFI via
  paramètre (ex: ?file=../../wp-config.php) auparavant manquées.
* Tests d'exécution du moteur (21 cas : body scanner, anti-IDOR, anti-injection,
  détection d'IP anti-spoofing, rate-limit, lockout brute-force) —
  `wordpress-plugin/tests/test-plugin.php`. Validé en attaques réelles sur
  WordPress (Playground) : prototype pollution, RCE, SSRF, DoS, honeypot,
  traversal, rate-limit et en-têtes de sécurité tous confirmés.

= 1.4.0 =
* Sécurité : durcissement de la détection d'IP cliente. Par défaut `REMOTE_ADDR`
  (non falsifiable) ; en-tête proxy lu uniquement si explicitement configuré.
  Corrige un contournement possible de la liste blanche, du rate-limit et du
  lockout brute-force par usurpation d'en-tête `X-Forwarded-For`.
* Réglage « En-tête IP de confiance » (Réglages → Réseau & IP).
* Store partagé distribué (KvStore + Upstash) côté SDK.

= 1.3.0 =
* Inspecteur de réponse + détection d'anomalies d'authentification (SDK).
* Suite de tests d'exécution PHP.

= 1.2.0 =
* Durcissement complet + moteur RLS portable + suite de tests.

= 1.1.0 =
* Alertes temps réel e-mail + Slack/Discord/Teams (webhook), avec seuil de
  gravité et anti-spam (throttling par menace).
* Anti-IDOR **sans code** : page admin pour déclarer les routes protégées
  (route, source de l'ID, table, colonne propriétaire, bypass par capacité) —
  vérification de propriété à chaque requête REST.

= 1.0.0 =
* Version initiale : body scanner, anti-IDOR (code), brute-force, rate-limit,
  honeypot, security headers, dashboard + journal.
