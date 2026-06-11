=== KeysO-WAF — Pare-feu applicatif surpuissant ===
Contributors: keyso
Tags: security, firewall, waf, brute-force, idor, ssrf, rce, hardening
Requires at least: 5.8
Tested up to: 6.7
Requires PHP: 8.0
Stable tag: 1.0.0
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
Oui. L'IP réelle est lue depuis `CF-Connecting-IP` / `X-Real-IP` / `X-Forwarded-For`.

== Changelog ==

= 1.1.0 =
* Alertes temps réel e-mail + Slack/Discord/Teams (webhook), avec seuil de
  gravité et anti-spam (throttling par menace).
* Anti-IDOR **sans code** : page admin pour déclarer les routes protégées
  (route, source de l'ID, table, colonne propriétaire, bypass par capacité) —
  vérification de propriété à chaque requête REST.

= 1.0.0 =
* Version initiale : body scanner, anti-IDOR (code), brute-force, rate-limit,
  honeypot, security headers, dashboard + journal.
