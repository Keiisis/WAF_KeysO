=== KeysO-WAF — Pare-feu applicatif surpuissant ===
Contributors: keyso
Tags: security, firewall, waf, brute-force, idor, ssrf, rce, hardening
Requires at least: 5.8
Tested up to: 6.7
Requires PHP: 8.0
Stable tag: 1.9.0
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

= 1.9.0 =
* Comble les 4 surfaces restantes (validé par attaques réelles) :
  - XSS : détection de <script>, gestionnaires on*, javascript:, <iframe>/<svg>
    dans les entrées GET et POST. Exempte les utilisateurs unfiltered_html
    (admins/éditeurs) pour zéro faux positif sur le contenu légitime.
  - Scanner d'UPLOAD (anti web-shell) : refuse extensions exécutables, doubles
    extensions (shell.php.jpg), code PHP embarqué, polyglotes (GIF+PHP),
    incohérences MIME. Validé : web-shell refusé sous 3 formes.
  - SQLi sur POST (option) avec la même garde anti-faux-positif.
  - admin-ajax.php couvert par le scan profond.
* Détection d'INTRUSION & transport (réduit l'impact d'une compromission) :
  - Alerte si siteurl/home est modifié (défacement / hijack post-intrusion).
  - Liaison de session optionnelle : un cookie admin rejoué depuis une autre IP
    est détecté → déconnexion (anti vol de session).
  - Forçage HTTPS admin + HSTS ; alertes de posture (PHP/WP obsolète, HTTPS).
* Honnêteté : un plugin ne peut PAS empêcher un serveur compromis, un vol de
  base par accès SSH, un détournement DNS ni un zero-day de WordPress core — il
  les DÉTECTE et en limite l'impact (2FA + mots de passe forts rendent une base
  volée inutile). Le « RLS » pour WordPress = le moteur d'ownership anti-IDOR.
* Tests portés à 48 cas (XSS inclus).

= 1.8.0 =
* Module SURFACES & limitation post-intrusion (couvre bien plus que wp-login) :
  - Éditeur de fichiers thèmes/extensions désactivé (DISALLOW_FILE_EDIT) → tue le
    vecteur RCE n°1 même si un compte admin est compromis.
  - Liste blanche d'IP pour wp-admin / wp-login : un identifiant admin VOLÉ
    devient inutile depuis une IP non autorisée (validé : 403 même avec le bon
    mot de passe). Défense ultime contre le vol d'identifiants.
  - Application Passwords refusés aux comptes 2FA (sinon ils contournent le 2nd
    facteur via l'API REST en Basic Auth).
  - Verrou optionnel installation/upload/suppression d'extensions & thèmes.
  - Blocage des chemins sensibles : via PHP (wp-config.bak, .git, debug.log…) ET
    via règles .htaccess auto-générées pour les fichiers STATIQUES servis par le
    serveur avant PHP (readme.html, license.txt, *.sql, *.bak, -Indexes).
  - Rate-limit de wp-cron.php (amplification DoS).
* DÉFENSE ACTIVE : auto-ban comportemental — une IP qui accumule N blocages
  (défaut 10/10 min) est bannie automatiquement (403) pour 1 h. Centralisé.
* Validé par ATTAQUES RÉELLES (WordPress + MySQL conteneurisé) :
  - hydra brute-force wp-login avec le vrai mot de passe en 8e position →
    « 0 valid password found » (lockout dès le 5e essai).
  - wpscan attaque par mot de passe (mdp faible dans la liste) → rien trouvé,
    étranglé par 429 + auto-ban ; énumération users & sauvegardes de config
    bloquées ; readme.html / license.txt → 403 via .htaccess.
  - Scénario « login admin volé » → 403 partout depuis IP non autorisée.
* Tests portés à 42 cas (auto-ban inclus).

= 1.7.1 =
* Sécurité : la double authentification couvre désormais XML-RPC. L'auth d'un
  compte 2FA via xmlrpc (qui ne peut pas transporter de code TOTP) est REFUSÉE,
  fermant le contournement du second facteur par system.multicall. Faille
  découverte et corrigée lors de tests d'attaque réels (wpscan) sur un
  WordPress + MySQL conteneurisé.
* Validation par attaques réelles : wpscan (attaque par mot de passe incluant un
  mot de passe faible connu) → « No Valid Passwords Found » + étranglement
  HTTP 429 ; brute-force wp-login → lockout (connexion refusée même avec le bon
  mot de passe) ; 2FA → login refusé sans code, accepté avec code TOTP valide ;
  SQLi / énumération / honeypot / en-têtes tous confirmés sur WordPress réel.

= 1.7.0 =
* DOUBLE AUTHENTIFICATION (2FA TOTP, RFC 6238) — compatible Google Authenticator,
  Authy, Microsoft Authenticator. Implémentation 100% PHP, aucun secret envoyé à
  un tiers. Enrôlement dans le profil utilisateur (clé secrète + confirmation par
  code) + 8 codes de secours à usage unique. Appliquée au login : même un mot de
  passe deviné ou cassé devient inutile sans le code à 6 chiffres. Validé contre
  le vecteur de test officiel RFC 6238.
* MOTS DE PASSE FORTS imposés (≥12 caractères, 3 classes de caractères, hors
  liste de mots de passe communs, différent de l'identifiant). Rend le cassage
  par dictionnaire — en ligne comme hors-ligne sur un hash volé — infaisable.
* Ces deux mesures répondent au scénario « base volée + mots de passe faibles » :
  on ne peut pas rendre un hash déjà fuité incassable, mais on empêche les mots
  de passe faibles d'exister ET on neutralise tout identifiant compromis via 2FA.
* Tests portés à 38 cas (TOTP, vecteur RFC, force des mots de passe inclus).

= 1.6.0 =
* Module DURCISSEMENT WordPress (protection cœur, toujours active) :
  - Détection d'INJECTION SQL sur les paramètres GET / la query string
    (UNION SELECT, boolean ' OR '1'='1, stacked ; DROP, time-based sleep(),
    error-based extractvalue…). Scan dé-slashé (wp_unslash) pour ne pas être
    contourné par les quotes échappées de WordPress.
  - Anti-ÉNUMÉRATION des utilisateurs : blocage de ?author=N et de l'endpoint
    REST /wp/v2/users pour les visiteurs non connectés (empêche la récolte des
    identifiants à cibler en brute-force).
  - Messages de login GÉNÉRIQUES (ne révèlent pas si un identifiant existe).
  - Surveillance d'INTÉGRITÉ : alerte lorsqu'un compte administrateur est créé
    ou qu'un utilisateur est élevé en admin (persistance post-intrusion).
  - Désactivation optionnelle de XML-RPC (vecteur brute-force / pingback DDoS).
* Tests portés à 29 cas (dont SQLi + anti-faux-positifs). Validé en attaques
  réelles sur WordPress : SQLi 6/6 bloquées, 0 faux positif sur contenu légitime.
* Note : WordPress stocke les mots de passe hachés (phpass/bcrypt) — ils ne
  peuvent pas être « récupérés » en clair, même avec un accès base. Ce module
  réduit la capacité à cibler et à persister ; il ne remplace pas HTTPS.

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
