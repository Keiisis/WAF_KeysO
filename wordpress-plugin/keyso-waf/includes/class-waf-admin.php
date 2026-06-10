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
        add_submenu_page('keyso-waf', __('Réglages', 'keyso-waf'), __('Réglages', 'keyso-waf'), 'manage_options', 'keyso-waf-settings', [$this, 'renderSettings']);
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
        foreach (['enabled','scan_rest_bodies','protect_login','rate_limit','block_honeypot','security_headers'] as $k) {
            $out[$k] = !empty($input[$k]) ? 1 : 0;
        }
        $out['login_max_attempts'] = max(1, (int)($input['login_max_attempts'] ?? $d['login_max_attempts']));
        $out['login_lockout_min']  = max(1, (int)($input['login_lockout_min'] ?? $d['login_lockout_min']));
        $out['rate_limit_max']     = max(10, (int)($input['rate_limit_max'] ?? $d['rate_limit_max']));
        $out['rate_limit_window']  = max(10, (int)($input['rate_limit_window'] ?? $d['rate_limit_window']));
        $out['whitelist_ips']      = sanitize_textarea_field($input['whitelist_ips'] ?? '');
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

            <h2><?php esc_html_e('Derniers événements', 'keyso-waf'); ?></h2>
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
                    $this->toggle($o, 'scan_rest_bodies', __('Analyse structurelle des requêtes (Prototype Pollution / RCE / SSRF / DoS)', 'keyso-waf'));
                    $this->toggle($o, 'protect_login', __('Protection brute-force (lockout login)', 'keyso-waf'));
                    $this->toggle($o, 'rate_limit', __('Limitation du débit par IP', 'keyso-waf'));
                    $this->toggle($o, 'block_honeypot', __('Blocage des chemins pièges (honeypot)', 'keyso-waf'));
                    $this->toggle($o, 'security_headers', __('En-têtes de sécurité HTTP', 'keyso-waf'));
                    $this->number($o, 'login_max_attempts', __('Tentatives login avant lockout', 'keyso-waf'));
                    $this->number($o, 'login_lockout_min', __('Durée du lockout (minutes)', 'keyso-waf'));
                    $this->number($o, 'rate_limit_max', __('Requêtes max par fenêtre', 'keyso-waf'));
                    $this->number($o, 'rate_limit_window', __('Fenêtre de rate-limit (secondes)', 'keyso-waf'));
                    ?>
                    <tr>
                        <th scope="row"><?php esc_html_e('IPs en liste blanche', 'keyso-waf'); ?></th>
                        <td>
                            <textarea name="keyso_waf_options[whitelist_ips]" rows="4" cols="40" class="large-text code"><?php echo esc_textarea((string)$o['whitelist_ips']); ?></textarea>
                            <p class="description"><?php esc_html_e('Une IP par ligne. Ces IPs sont exemptées de tout blocage.', 'keyso-waf'); ?></p>
                        </td>
                    </tr>
                </table>
                <?php submit_button(); ?>
            </form>
        </div>
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
