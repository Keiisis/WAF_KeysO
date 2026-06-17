<?php
/**
 * KeysO-WAF — Interface d'administration (réglages + tableau de bord).
 *
 * @package KeysO_WAF
 */

namespace KeysO_WAF;

if (!defined('ABSPATH')) exit;

final class Admin
{
    public function boot(): void
    {
        add_action('admin_menu', [$this, 'menu']);
        add_action('admin_init', [$this, 'registerSettings']);
        add_action('admin_enqueue_scripts', [$this, 'assets']);
        add_action('admin_post_keyso_waf_export_logs', [$this, 'exportLogs']);
    }

    /** Export CSV du journal de sécurité (admin + nonce). */
    public function exportLogs(): void
    {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('Accès refusé.', 'keyso-waf'), '', ['response' => 403]);
        }
        check_admin_referer('keyso_waf_export_logs');

        $rows = Logger::recent(5000);
        nocache_headers();
        header('Content-Type: text/csv; charset=utf-8');
        header('Content-Disposition: attachment; filename="keyso-waf-logs-' . gmdate('Ymd-His') . '.csv"');
        $out = fopen('php://output', 'w');
        fprintf($out, "\xEF\xBB\xBF"); // BOM UTF-8
        fputcsv($out, ['Date', 'IP', 'Méthode', 'Menace', 'Action', 'Chemin', 'Détail', 'User-Agent']);
        foreach ($rows as $r) {
            fputcsv($out, [
                $r->created_at ?? '', $r->ip ?? '', $r->method ?? '', $r->threat ?? '',
                $r->action ?? '', $r->path ?? '', $r->detail ?? '', $r->user_agent ?? '',
            ]);
        }
        fclose($out);
        exit;
    }

    /** Page d'activation de licence (anti-piratage). */
    public function renderLicense(): void
    {
        if (isset($_POST['keyso_license_nonce']) && wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['keyso_license_nonce'])), 'keyso_license')) {
            if (isset($_POST['activate'])) {
                $res = License::activate(sanitize_text_field(wp_unslash($_POST['license_key'] ?? '')));
            } elseif (isset($_POST['deactivate'])) {
                $res = License::deactivate();
            }
            if (isset($res)) {
                $cls = !empty($res['success']) ? 'notice-success' : 'notice-error';
                echo '<div class="notice ' . esc_attr($cls) . ' is-dismissible"><p>' . esc_html($res['message']) . '</p></div>';
            }
        }

        $status = License::status();
        $isPro  = License::isPro();
        $key    = License::key();
        ?>
        <div class="wrap keyso-waf">
            <h1>🔑 KeysO-WAF — <?php esc_html_e('Licence', 'keyso-waf'); ?></h1>
            <p>
                <?php esc_html_e('Statut :', 'keyso-waf'); ?>
                <strong style="color:<?php echo $isPro ? '#008751' : '#E8112D'; ?>">
                    <?php echo esc_html($isPro ? __('Active (Premium)', 'keyso-waf') : ($status === 'invalid' ? __('Invalide', 'keyso-waf') : __('Inactive (mode communautaire)', 'keyso-waf'))); ?>
                </strong>
            </p>
            <p class="description" style="max-width:720px">
                <?php esc_html_e('La protection cœur (analyse des requêtes, brute-force, rate-limit, honeypot, en-têtes) est TOUJOURS active. Une licence valide débloque les fonctions premium : alertes temps réel (e-mail/Slack) et anti-IDOR sans code.', 'keyso-waf'); ?>
            </p>
            <form method="post" style="margin-top:16px">
                <?php wp_nonce_field('keyso_license', 'keyso_license_nonce'); ?>
                <table class="form-table" role="presentation">
                    <tr>
                        <th scope="row"><?php esc_html_e('Clé de licence', 'keyso-waf'); ?></th>
                        <td><input type="text" name="license_key" value="<?php echo esc_attr($key); ?>" class="regular-text code" placeholder="KEYSO-XXXX-XXXX-XXXX" <?php disabled($isPro); ?> /></td>
                    </tr>
                </table>
                <?php if ($isPro): ?>
                    <button type="submit" name="deactivate" class="button"><?php esc_html_e('Désactiver sur ce domaine', 'keyso-waf'); ?></button>
                <?php else: ?>
                    <button type="submit" name="activate" class="button button-primary"><?php esc_html_e('Activer la licence', 'keyso-waf'); ?></button>
                <?php endif; ?>
            </form>
            <?php if (License::apiUrl() === ''): ?>
                <div class="notice notice-info inline" style="margin-top:16px"><p>
                    <?php esc_html_e('Aucun serveur de licence configuré (constante KEYSO_WAF_LICENSE_API). En mode communautaire, la protection cœur fonctionne ; les fonctions premium restent désactivées.', 'keyso-waf'); ?>
                </p></div>
            <?php endif; ?>
        </div>
        <?php
    }

    public function menu(): void
    {
        add_menu_page(
            'KeysO-WAF',
            'KeysO-WAF',
            'manage_options',
            'keyso-waf',
            [$this, 'renderDashboard'],
            'dashicons-shield-alt',
            80
        );
        add_submenu_page('keyso-waf', __('Tableau de bord', 'keyso-waf'), __('Tableau de bord', 'keyso-waf'), 'manage_options', 'keyso-waf', [$this, 'renderDashboard']);
        add_submenu_page('keyso-waf', __('Anti-IDOR', 'keyso-waf'), __('Anti-IDOR', 'keyso-waf'), 'manage_options', 'keyso-waf-idor', [$this, 'renderIdor']);
        add_submenu_page('keyso-waf', __('Réglages', 'keyso-waf'), __('Réglages', 'keyso-waf'), 'manage_options', 'keyso-waf-settings', [$this, 'renderSettings']);
        add_submenu_page('keyso-waf', __('Licence', 'keyso-waf'), __('Licence', 'keyso-waf'), 'manage_options', 'keyso-waf-license', [$this, 'renderLicense']);
    }

    public function assets($hook): void
    {
        if (strpos((string)$hook, 'keyso-waf') === false) return;
        wp_enqueue_style('keyso-waf-admin', KEYSO_WAF_URL . 'assets/admin.css', [], KEYSO_WAF_VERSION);
    }

    public function registerSettings(): void
    {
        register_setting('keyso_waf_group', 'keyso_waf_options', [$this, 'sanitize']);
    }

    /** @param mixed $input */
    public function sanitize($input): array
    {
        $d = keyso_waf_default_options();
        $out = [];
        foreach (['enabled','scan_rest_bodies','scan_front_post','protect_login','rate_limit','block_honeypot','security_headers','alerts_enabled','idor_enabled','sqli_detection','block_user_enum','generic_login_errors','disable_xmlrpc','db_integrity_alerts','enforce_strong_passwords','two_factor','disable_file_editor','lock_plugin_theme_install','restrict_app_passwords','protect_sensitive_paths','auto_ban_enabled'] as $k) {
            $out[$k] = !empty($input[$k]) ? 1 : 0;
        }
        $out['admin_ip_allowlist'] = sanitize_textarea_field($input['admin_ip_allowlist'] ?? '');
        $out['auto_ban_threshold'] = max(3, (int)($input['auto_ban_threshold'] ?? 10));
        $out['auto_ban_window']    = max(60, (int)($input['auto_ban_window'] ?? 600));
        $out['auto_ban_duration']  = max(60, (int)($input['auto_ban_duration'] ?? 3600));
        $out['blocklist_ips'] = sanitize_textarea_field($input['blocklist_ips'] ?? '');
        $out['block_message'] = sanitize_text_field($input['block_message'] ?? '');
        $out['login_max_attempts'] = max(1, (int)($input['login_max_attempts'] ?? $d['login_max_attempts']));
        $out['login_lockout_min']  = max(1, (int)($input['login_lockout_min'] ?? $d['login_lockout_min']));
        $out['rate_limit_max']     = max(10, (int)($input['rate_limit_max'] ?? $d['rate_limit_max']));
        $out['rate_limit_window']  = max(10, (int)($input['rate_limit_window'] ?? $d['rate_limit_window']));
        $out['whitelist_ips']      = sanitize_textarea_field($input['whitelist_ips'] ?? '');

        // En-tête IP de confiance : liste blanche stricte (anti-spoofing)
        $allowedHeaders = ['', 'HTTP_CF_CONNECTING_IP', 'HTTP_TRUE_CLIENT_IP', 'HTTP_X_REAL_IP', 'HTTP_X_FORWARDED_FOR'];
        $th = (string)($input['trusted_ip_header'] ?? '');
        $out['trusted_ip_header'] = in_array($th, $allowedHeaders, true) ? $th : '';

        // ── Alertes ──
        $out['alerts_email']         = sanitize_email($input['alerts_email'] ?? '');
        $out['alerts_slack_webhook'] = esc_url_raw($input['alerts_slack_webhook'] ?? '');
        $out['alerts_min_severity']  = max(1, min(4, (int)($input['alerts_min_severity'] ?? $d['alerts_min_severity'])));
        $out['alerts_throttle_min']  = max(1, (int)($input['alerts_throttle_min'] ?? $d['alerts_throttle_min']));
        return $out;
    }

    public function renderDashboard(): void
    {
        $stats  = Logger::stats();
        $recent = Logger::recent(100);
        $total  = array_sum($stats);
        ?>
        <div class="wrap keyso-waf">
            <h1>🛡️ KeysO-WAF — <?php esc_html_e('Tableau de bord', 'keyso-waf'); ?></h1>

            <div class="keyso-cards">
                <div class="keyso-card">
                    <div class="keyso-num"><?php echo esc_html((string)$total); ?></div>
                    <div class="keyso-lbl"><?php esc_html_e('Menaces bloquées (30 j)', 'keyso-waf'); ?></div>
                </div>
                <?php foreach (array_slice($stats, 0, 4, true) as $threat => $n): ?>
                    <div class="keyso-card">
                        <div class="keyso-num"><?php echo esc_html((string)$n); ?></div>
                        <div class="keyso-lbl"><?php echo esc_html($threat); ?></div>
                    </div>
                <?php endforeach; ?>
            </div>

            <h2 style="display:flex;align-items:center;gap:12px">
                <?php esc_html_e('Derniers événements', 'keyso-waf'); ?>
                <a href="<?php echo esc_url(wp_nonce_url(admin_url('admin-post.php?action=keyso_waf_export_logs'), 'keyso_waf_export_logs')); ?>"
                   class="button button-secondary" style="font-size:12px">⬇ <?php esc_html_e('Exporter (CSV)', 'keyso-waf'); ?></a>
            </h2>
            <table class="widefat striped keyso-logs">
                <thead>
                    <tr>
                        <th><?php esc_html_e('Date', 'keyso-waf'); ?></th>
                        <th><?php esc_html_e('IP', 'keyso-waf'); ?></th>
                        <th><?php esc_html_e('Menace', 'keyso-waf'); ?></th>
                        <th><?php esc_html_e('Chemin', 'keyso-waf'); ?></th>
                        <th><?php esc_html_e('Détail', 'keyso-waf'); ?></th>
                    </tr>
                </thead>
                <tbody>
                    <?php if (empty($recent)): ?>
                        <tr><td colspan="5"><?php esc_html_e('Aucun événement — votre site est calme. 🎉', 'keyso-waf'); ?></td></tr>
                    <?php else: foreach ($recent as $r): ?>
                        <tr>
                            <td><?php echo esc_html($r->created_at); ?></td>
                            <td><code><?php echo esc_html($r->ip); ?></code></td>
                            <td><span class="keyso-tag"><?php echo esc_html($r->threat); ?></span></td>
                            <td><code><?php echo esc_html(mb_substr((string)$r->path, 0, 60)); ?></code></td>
                            <td><?php echo esc_html(mb_substr((string)$r->detail, 0, 90)); ?></td>
                        </tr>
                    <?php endforeach; endif; ?>
                </tbody>
            </table>
        </div>
        <?php
    }

    public function renderSettings(): void
    {
        $o = keyso_waf_get_options();
        ?>
        <div class="wrap keyso-waf">
            <h1>🛡️ KeysO-WAF — <?php esc_html_e('Réglages', 'keyso-waf'); ?></h1>
            <form method="post" action="options.php">
                <?php settings_fields('keyso_waf_group'); ?>
                <table class="form-table" role="presentation">
                    <?php
                    $this->toggle($o, 'enabled', __('Activer le pare-feu', 'keyso-waf'));
                    $this->toggle($o, 'scan_rest_bodies', __('Analyse structurelle des requêtes REST (Prototype Pollution / RCE / SSRF / DoS)', 'keyso-waf'));
                    $this->toggle($o, 'scan_front_post', __('Analyser aussi les POST de formulaires front (hors REST)', 'keyso-waf'));
                    $this->toggle($o, 'protect_login', __('Protection brute-force (lockout login)', 'keyso-waf'));
                    $this->toggle($o, 'rate_limit', __('Limitation du débit par IP', 'keyso-waf'));
                    $this->toggle($o, 'block_honeypot', __('Blocage des chemins pièges (honeypot)', 'keyso-waf'));
                    $this->toggle($o, 'security_headers', __('En-têtes de sécurité HTTP', 'keyso-waf'));
                    ?>
                    <tr><th colspan="2"><h2 style="margin:18px 0 0"><?php esc_html_e('🔒 Durcissement WordPress', 'keyso-waf'); ?></h2></th></tr>
                    <?php
                    $this->toggle($o, 'sqli_detection', __('Détection d\'injection SQL (paramètres GET / URL)', 'keyso-waf'));
                    $this->toggle($o, 'block_user_enum', __('Anti-énumération des utilisateurs (?author=, REST /users)', 'keyso-waf'));
                    $this->toggle($o, 'generic_login_errors', __('Messages de login génériques (ne révèle pas les identifiants valides)', 'keyso-waf'));
                    $this->toggle($o, 'db_integrity_alerts', __('Alerte intégrité : création / élévation d\'un administrateur', 'keyso-waf'));
                    $this->toggle($o, 'disable_xmlrpc', __('Désactiver XML-RPC (recommandé si ni Jetpack ni app mobile)', 'keyso-waf'));
                    $this->toggle($o, 'enforce_strong_passwords', __('Imposer des mots de passe forts (≥12 car., contre le cassage par dictionnaire)', 'keyso-waf'));
                    $this->toggle($o, 'two_factor', __('Double authentification (2FA TOTP) — enrôlement dans chaque profil utilisateur', 'keyso-waf'));
                    ?>
                    <tr><th colspan="2"><h2 style="margin:18px 0 0"><?php esc_html_e('🧱 Surfaces & limitation post-intrusion', 'keyso-waf'); ?></h2></th></tr>
                    <?php
                    $this->toggle($o, 'disable_file_editor', __('Désactiver l\'éditeur de fichiers thèmes/extensions (anti-RCE si admin compromis)', 'keyso-waf'));
                    $this->toggle($o, 'restrict_app_passwords', __('Refuser les Application Passwords aux comptes 2FA (anti-contournement API)', 'keyso-waf'));
                    $this->toggle($o, 'protect_sensitive_paths', __('Bloquer les chemins sensibles (readme.html, *.sql, *.bak, debug.log, .git…)', 'keyso-waf'));
                    $this->toggle($o, 'lock_plugin_theme_install', __('Verrouiller installation/upload/suppression d\'extensions & thèmes (limite un admin volé)', 'keyso-waf'));
                    ?>
                    <tr>
                        <th scope="row"><?php esc_html_e('Liste blanche IP — wp-admin / wp-login', 'keyso-waf'); ?></th>
                        <td>
                            <textarea name="keyso_waf_options[admin_ip_allowlist]" rows="3" cols="40" class="large-text code"><?php echo esc_textarea((string)($o['admin_ip_allowlist'] ?? '')); ?></textarea>
                            <p class="description"><?php esc_html_e('Une IP par ligne. Si renseigné, SEULES ces IP peuvent atteindre l\'administration et le login — un identifiant volé devient inutile ailleurs. ⚠️ Laissez vide si votre IP change, au risque de vous bloquer.', 'keyso-waf'); ?></p>
                        </td>
                    </tr>
                    <tr><th colspan="2"><h2 style="margin:18px 0 0"><?php esc_html_e('🛡️ Défense active (auto-ban)', 'keyso-waf'); ?></h2></th></tr>
                    <?php
                    $this->toggle($o, 'auto_ban_enabled', __('Bannir automatiquement une IP qui accumule des blocages', 'keyso-waf'));
                    $this->number($o, 'auto_ban_threshold', __('Nombre de blocages avant ban', 'keyso-waf'));
                    $this->number($o, 'auto_ban_window', __('Fenêtre d\'observation (secondes)', 'keyso-waf'));
                    $this->number($o, 'auto_ban_duration', __('Durée du ban (secondes)', 'keyso-waf'));
                    $this->number($o, 'login_max_attempts', __('Tentatives login avant lockout', 'keyso-waf'));
                    $this->number($o, 'login_lockout_min', __('Durée du lockout (minutes)', 'keyso-waf'));
                    $this->number($o, 'rate_limit_max', __('Requêtes max par fenêtre', 'keyso-waf'));
                    $this->number($o, 'rate_limit_window', __('Fenêtre de rate-limit (secondes)', 'keyso-waf'));
                    ?>
                    <tr><th colspan="2"><h2 style="margin:18px 0 0"><?php esc_html_e('🔔 Alertes temps réel', 'keyso-waf'); ?></h2></th></tr>
                    <?php
                    $this->toggle($o, 'alerts_enabled', __('Activer les alertes (e-mail / Slack)', 'keyso-waf'));
                    ?>
                    <tr>
                        <th scope="row"><?php esc_html_e('E-mail destinataire', 'keyso-waf'); ?></th>
                        <td><input type="email" name="keyso_waf_options[alerts_email]" value="<?php echo esc_attr((string)$o['alerts_email']); ?>" class="regular-text" placeholder="<?php echo esc_attr(get_option('admin_email')); ?>" /></td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e('Webhook Slack / Discord / Teams', 'keyso-waf'); ?></th>
                        <td>
                            <input type="url" name="keyso_waf_options[alerts_slack_webhook]" value="<?php echo esc_attr((string)$o['alerts_slack_webhook']); ?>" class="large-text code" placeholder="https://hooks.slack.com/services/..." />
                            <p class="description"><?php esc_html_e('Collez l\'URL du webhook entrant. Compatible Slack, Discord (avec /slack), Mattermost.', 'keyso-waf'); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e('Gravité minimale (1–4)', 'keyso-waf'); ?></th>
                        <td><input type="number" min="1" max="4" name="keyso_waf_options[alerts_min_severity]" value="<?php echo esc_attr((string)$o['alerts_min_severity']); ?>" class="small-text" />
                        <span class="description"><?php esc_html_e('1=info · 2=modéré · 3=élevé · 4=critique', 'keyso-waf'); ?></span></td>
                    </tr>
                    <?php
                    $this->number($o, 'alerts_throttle_min', __('Anti-spam : 1 alerte / menace / X minutes', 'keyso-waf'));
                    ?>
                    <tr><th colspan="2"><h2 style="margin:18px 0 0"><?php esc_html_e('🌐 Réseau & IP', 'keyso-waf'); ?></h2></th></tr>
                    <tr>
                        <th scope="row"><?php esc_html_e('En-tête IP de confiance', 'keyso-waf'); ?></th>
                        <td>
                            <?php $th = (string)($o['trusted_ip_header'] ?? ''); ?>
                            <select name="keyso_waf_options[trusted_ip_header]">
                                <option value="" <?php selected($th, ''); ?>><?php esc_html_e('REMOTE_ADDR (recommandé — aucun proxy)', 'keyso-waf'); ?></option>
                                <option value="HTTP_CF_CONNECTING_IP" <?php selected($th, 'HTTP_CF_CONNECTING_IP'); ?>>Cloudflare (CF-Connecting-IP)</option>
                                <option value="HTTP_TRUE_CLIENT_IP" <?php selected($th, 'HTTP_TRUE_CLIENT_IP'); ?>>True-Client-IP (Akamai/Cloudflare Enterprise)</option>
                                <option value="HTTP_X_REAL_IP" <?php selected($th, 'HTTP_X_REAL_IP'); ?>>X-Real-IP (Nginx)</option>
                                <option value="HTTP_X_FORWARDED_FOR" <?php selected($th, 'HTTP_X_FORWARDED_FOR'); ?>>X-Forwarded-For</option>
                            </select>
                            <p class="description"><?php esc_html_e("⚠️ Laissez sur REMOTE_ADDR sauf si votre site est RÉELLEMENT derrière ce proxy/CDN. Sinon, un attaquant falsifie son IP et contourne la liste blanche, le rate-limit et le lockout brute-force.", 'keyso-waf'); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e('IPs en liste blanche', 'keyso-waf'); ?></th>
                        <td>
                            <textarea name="keyso_waf_options[whitelist_ips]" rows="4" cols="40" class="large-text code"><?php echo esc_textarea((string)$o['whitelist_ips']); ?></textarea>
                            <p class="description"><?php esc_html_e('Une IP par ligne. Ces IPs sont exemptées de tout blocage.', 'keyso-waf'); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e('IPs en liste noire', 'keyso-waf'); ?></th>
                        <td>
                            <textarea name="keyso_waf_options[blocklist_ips]" rows="4" cols="40" class="large-text code"><?php echo esc_textarea((string)($o['blocklist_ips'] ?? '')); ?></textarea>
                            <p class="description"><?php esc_html_e('Une IP par ligne. Ces IPs sont bloquées immédiatement (403) sur tout le site.', 'keyso-waf'); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e('Message de blocage', 'keyso-waf'); ?></th>
                        <td>
                            <input type="text" name="keyso_waf_options[block_message]" value="<?php echo esc_attr((string)($o['block_message'] ?? '')); ?>" class="large-text" placeholder="<?php esc_attr_e('Requête bloquée par le pare-feu applicatif.', 'keyso-waf'); ?>" />
                            <p class="description"><?php esc_html_e('Texte affiché aux requêtes bloquées (laisser vide pour le message par défaut).', 'keyso-waf'); ?></p>
                        </td>
                    </tr>
                </table>
                <?php submit_button(); ?>
            </form>
        </div>
        <?php
    }

    public function renderIdor(): void
    {
        // ── Sauvegarde (formulaire array → option dédiée) ──
        if (isset($_POST['keyso_idor_nonce']) && wp_verify_nonce($_POST['keyso_idor_nonce'], 'keyso_idor_save')) {
            $rules = IdorRules::sanitizeRules(wp_unslash($_POST['rules'] ?? []));
            update_option(IdorRules::OPTION, $rules);

            // Activer/désactiver le module
            $o = keyso_waf_get_options();
            $o['idor_enabled'] = !empty($_POST['idor_enabled']) ? 1 : 0;
            update_option('keyso_waf_options', $o);

            echo '<div class="notice notice-success is-dismissible"><p>'
                . esc_html__('Règles anti-IDOR enregistrées.', 'keyso-waf') . '</p></div>';
        }

        $o     = keyso_waf_get_options();
        $rules = IdorRules::getRules();
        $rules[] = []; // ligne vide pour ajout
        ?>
        <div class="wrap keyso-waf">
            <h1>🔐 KeysO-WAF — <?php esc_html_e('Anti-IDOR (sans code)', 'keyso-waf'); ?></h1>
            <p class="description" style="max-width:760px">
                <?php esc_html_e("Déclarez quelles routes REST exposent des ressources possédées par un utilisateur. KeysO-WAF vérifiera, à chaque requête, que l'utilisateur connecté est bien le propriétaire — sinon la ressource est masquée (404). Aucune ligne de code requise.", 'keyso-waf'); ?>
            </p>

            <form method="post">
                <?php wp_nonce_field('keyso_idor_save', 'keyso_idor_nonce'); ?>

                <p>
                    <label class="keyso-switch">
                        <input type="checkbox" name="idor_enabled" value="1" <?php checked(!empty($o['idor_enabled'])); ?> />
                        <span></span>
                    </label>
                    <strong style="vertical-align:super;margin-left:8px"><?php esc_html_e('Activer la protection anti-IDOR', 'keyso-waf'); ?></strong>
                </p>

                <table class="widefat striped keyso-idor-table">
                    <thead>
                        <tr>
                            <th><?php esc_html_e('Libellé', 'keyso-waf'); ?></th>
                            <th><?php esc_html_e('Route contient', 'keyso-waf'); ?></th>
                            <th><?php esc_html_e('ID depuis', 'keyso-waf'); ?></th>
                            <th><?php esc_html_e('Param', 'keyso-waf'); ?></th>
                            <th><?php esc_html_e('Table', 'keyso-waf'); ?></th>
                            <th><?php esc_html_e('Col. ID', 'keyso-waf'); ?></th>
                            <th><?php esc_html_e('Col. propriétaire', 'keyso-waf'); ?></th>
                            <th><?php esc_html_e('Bypass (capacité)', 'keyso-waf'); ?></th>
                        </tr>
                    </thead>
                    <tbody id="keyso-idor-rows">
                        <?php foreach ($rules as $i => $r): ?>
                            <tr>
                                <td><input type="text" name="rules[<?php echo (int)$i; ?>][label]" value="<?php echo esc_attr($r['label'] ?? ''); ?>" placeholder="Commandes WooCommerce" /></td>
                                <td><input type="text" name="rules[<?php echo (int)$i; ?>][match]" value="<?php echo esc_attr($r['match'] ?? ''); ?>" placeholder="/wc/v3/orders/" /></td>
                                <td>
                                    <select name="rules[<?php echo (int)$i; ?>][id_source]">
                                        <option value="end_of_path" <?php selected(($r['id_source'] ?? '') === 'end_of_path'); ?>><?php esc_html_e('Fin de l\'URL', 'keyso-waf'); ?></option>
                                        <option value="query_param" <?php selected(($r['id_source'] ?? '') === 'query_param'); ?>><?php esc_html_e('Paramètre', 'keyso-waf'); ?></option>
                                    </select>
                                </td>
                                <td><input type="text" name="rules[<?php echo (int)$i; ?>][id_param]" value="<?php echo esc_attr($r['id_param'] ?? ''); ?>" placeholder="id" size="6" /></td>
                                <td><input type="text" name="rules[<?php echo (int)$i; ?>][table]" value="<?php echo esc_attr($r['table'] ?? ''); ?>" placeholder="posts" /></td>
                                <td><input type="text" name="rules[<?php echo (int)$i; ?>][id_column]" value="<?php echo esc_attr($r['id_column'] ?? 'ID'); ?>" size="6" /></td>
                                <td><input type="text" name="rules[<?php echo (int)$i; ?>][owner_column]" value="<?php echo esc_attr($r['owner_column'] ?? ''); ?>" placeholder="post_author" /></td>
                                <td><input type="text" name="rules[<?php echo (int)$i; ?>][staff_cap]" value="<?php echo esc_attr($r['staff_cap'] ?? ''); ?>" placeholder="manage_options" /></td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>

                <p>
                    <button type="button" class="button" id="keyso-idor-add">+ <?php esc_html_e('Ajouter une règle', 'keyso-waf'); ?></button>
                </p>

                <p class="description" style="max-width:760px">
                    <strong><?php esc_html_e('Exemple', 'keyso-waf'); ?> :</strong>
                    <?php esc_html_e('Route contient', 'keyso-waf'); ?> <code>/wc/v3/orders/</code> ·
                    <?php esc_html_e('ID depuis', 'keyso-waf'); ?> = <em><?php esc_html_e('Fin de l\'URL', 'keyso-waf'); ?></em> ·
                    <?php esc_html_e('Table', 'keyso-waf'); ?> <code>posts</code> ·
                    <?php esc_html_e('Col. ID', 'keyso-waf'); ?> <code>ID</code> ·
                    <?php esc_html_e('Col. propriétaire', 'keyso-waf'); ?> <code>post_author</code>.
                </p>

                <?php submit_button(__('Enregistrer les règles', 'keyso-waf')); ?>
            </form>
        </div>

        <script>
        (function () {
            var btn = document.getElementById('keyso-idor-add');
            var body = document.getElementById('keyso-idor-rows');
            if (!btn || !body) return;
            btn.addEventListener('click', function () {
                var idx = body.querySelectorAll('tr').length;
                var tr = document.createElement('tr');
                tr.innerHTML =
                    '<td><input type="text" name="rules['+idx+'][label]" placeholder="Libellé"></td>' +
                    '<td><input type="text" name="rules['+idx+'][match]" placeholder="/wc/v3/orders/"></td>' +
                    '<td><select name="rules['+idx+'][id_source]"><option value="end_of_path"><?php echo esc_js(__('Fin de l\'URL', 'keyso-waf')); ?></option><option value="query_param"><?php echo esc_js(__('Paramètre', 'keyso-waf')); ?></option></select></td>' +
                    '<td><input type="text" name="rules['+idx+'][id_param]" size="6"></td>' +
                    '<td><input type="text" name="rules['+idx+'][table]" placeholder="posts"></td>' +
                    '<td><input type="text" name="rules['+idx+'][id_column]" value="ID" size="6"></td>' +
                    '<td><input type="text" name="rules['+idx+'][owner_column]" placeholder="post_author"></td>' +
                    '<td><input type="text" name="rules['+idx+'][staff_cap]" placeholder="manage_options"></td>';
                body.appendChild(tr);
            });
        })();
        </script>
        <?php
    }

    private function toggle(array $o, string $key, string $label): void
    {
        ?>
        <tr>
            <th scope="row"><?php echo esc_html($label); ?></th>
            <td>
                <label class="keyso-switch">
                    <input type="checkbox" name="keyso_waf_options[<?php echo esc_attr($key); ?>]" value="1" <?php checked(!empty($o[$key])); ?> />
                    <span></span>
                </label>
            </td>
        </tr>
        <?php
    }

    private function number(array $o, string $key, string $label): void
    {
        ?>
        <tr>
            <th scope="row"><?php echo esc_html($label); ?></th>
            <td>
                <input type="number" min="1" name="keyso_waf_options[<?php echo esc_attr($key); ?>]" value="<?php echo esc_attr((string)$o[$key]); ?>" class="small-text" />
            </td>
        </tr>
        <?php
    }
}
