<?php
/**
 * KeysO-WAF — Anti-IDOR no-code (règles pilotées depuis l'admin).
 *
 * L'administrateur déclare, sans coder, quelles routes REST exposent des
 * ressources possédées par un utilisateur, et où trouver le propriétaire.
 * À l'exécution, KeysO-WAF intercepte ces routes et refuse l'accès si
 * l'utilisateur courant n'est pas le propriétaire (anti-IDOR / BOLA).
 *
 * S'appuie sur le core portable WafCore\Ownership.
 *
 * @package KeysO_WAF
 */

namespace KeysO_WAF;

use WafCore\Ownership;

if (!defined('ABSPATH')) exit;

final class IdorRules
{
    public const OPTION = 'keyso_waf_idor_rules';

    /** @return array<int,array<string,mixed>> */
    public static function getRules(): array
    {
        $rules = get_option(self::OPTION, []);
        return is_array($rules) ? $rules : [];
    }

    /**
     * Branche la protection sur les requêtes REST si activée et configurée.
     */
    public function boot(): void
    {
        $rules = self::getRules();
        if (empty($rules)) {
            return;
        }
        add_filter('rest_pre_dispatch', [$this, 'guard'], 6, 3);
    }

    /**
     * Intercepte chaque requête REST et applique les règles correspondantes.
     *
     * @param mixed            $result
     * @param \WP_REST_Server  $server
     * @param \WP_REST_Request $request
     * @return mixed
     */
    public function guard($result, $server, $request)
    {
        if ($result !== null) {
            return $result; // une réponse/erreur est déjà fixée
        }

        $route = (string) $request->get_route(); // ex: /wc/v3/orders/123
        foreach (self::getRules() as $rule) {
            $match = (string)($rule['match'] ?? '');
            if ($match === '' || strpos($route, $match) === false) {
                continue;
            }

            // 1. Extraire l'identifiant de la ressource
            $resourceId = $this->extractId($rule, $route, $request);
            if ($resourceId === '') {
                continue; // pas d'ID → la règle ne s'applique pas (ex: liste)
            }

            // 2. Bypass staff (capacité WordPress)
            $cap = (string)($rule['staff_cap'] ?? '');
            if ($cap !== '' && current_user_can($cap)) {
                continue;
            }

            // 3. Résoudre le propriétaire via wpdb (noms validés ci-dessous)
            $resolver = $this->makeResolver($rule);

            $verdict = Ownership::verify($resolver, [
                'userId'       => (string) get_current_user_id(),
                'resourceType' => (string)($rule['label'] ?? 'resource'),
                'resourceId'   => $resourceId,
            ], [
                // ressource introuvable → on laisse WordPress répondre son 404 naturel
                'missingPolicy' => 'allow',
            ]);

            if (!$verdict['allowed']) {
                Logger::log([
                    'ip'         => Guard::staticClientIp(),
                    'method'     => $_SERVER['REQUEST_METHOD'] ?? '',
                    'path'       => $route . ' [idor-rule]',
                    'threat'     => 'idor',
                    'detail'     => $verdict['detail'],
                    'action'     => 'block',
                    'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
                ]);
                // 404 plutôt que 403 : ne révèle pas l'existence de la ressource
                return new \WP_Error(
                    'keyso_waf_idor',
                    __('Ressource introuvable.', 'keyso-waf'),
                    ['status' => 404]
                );
            }
        }

        return $result;
    }

    /** Extrait l'ID selon la source configurée. */
    private function extractId(array $rule, string $route, $request): string
    {
        $source = (string)($rule['id_source'] ?? 'end_of_path');

        if ($source === 'query_param') {
            $param = (string)($rule['id_param'] ?? 'id');
            $val = $request->get_param($param);
            return is_scalar($val) ? (string) $val : '';
        }

        // end_of_path : dernier segment de l'URL (numérique ou UUID)
        $segments = array_values(array_filter(explode('/', $route)));
        $last = end($segments);
        if ($last === false) return '';
        $last = (string) $last;
        if (preg_match('/^\d+$/', $last) || preg_match('/^[0-9a-f-]{36}$/i', $last)) {
            return $last;
        }
        return '';
    }

    /**
     * Construit un resolver d'ownership wpdb à partir d'une règle.
     * SÉCURITÉ : table/colonnes ne sont PAS paramétrables en SQL → on les
     * valide en liste blanche stricte (alphanum + underscore) pour empêcher
     * toute injection via la configuration admin elle-même.
     */
    private function makeResolver(array $rule): callable
    {
        $table  = self::safeIdent((string)($rule['table'] ?? ''));
        $idCol  = self::safeIdent((string)($rule['id_column'] ?? 'ID'));
        $ownCol = self::safeIdent((string)($rule['owner_column'] ?? ''));

        return function (array $q) use ($table, $idCol, $ownCol): array {
            global $wpdb;
            if ($table === '' || $ownCol === '' || $idCol === '') {
                // config incomplète → fail-closed (le core refusera)
                return ['ownerId' => null, 'notFound' => false, 'ownerId_invalid' => true];
            }
            $fullTable = self::resolveTable($table);
            // Identifiants validés en amont → interpolation sûre ; valeur paramétrée.
            $sql = "SELECT `{$ownCol}` FROM `{$fullTable}` WHERE `{$idCol}` = %s LIMIT 1";
            $owner = $wpdb->get_var($wpdb->prepare($sql, $q['resourceId']));
            return [
                'ownerId'  => $owner !== null ? (string) $owner : null,
                'notFound' => $owner === null,
            ];
        };
    }

    /** Préfixe la table avec celui de WordPress si nécessaire. */
    private static function resolveTable(string $table): string
    {
        global $wpdb;
        if (str_starts_with($table, $wpdb->prefix)) {
            return $table;
        }
        return $wpdb->prefix . $table;
    }

    /** Liste blanche : ne garde que [a-zA-Z0-9_]. Anti-injection d'identifiant. */
    public static function safeIdent(string $name): string
    {
        return preg_replace('/[^a-zA-Z0-9_]/', '', $name) ?? '';
    }

    /**
     * Nettoie un tableau de règles soumis depuis l'admin.
     *
     * @param mixed $input
     * @return array<int,array<string,mixed>>
     */
    public static function sanitizeRules($input): array
    {
        if (!is_array($input)) return [];
        $out = [];
        foreach ($input as $row) {
            if (!is_array($row)) continue;
            $label = sanitize_text_field($row['label'] ?? '');
            $match = sanitize_text_field($row['match'] ?? '');
            $table = self::safeIdent($row['table'] ?? '');
            $own   = self::safeIdent($row['owner_column'] ?? '');
            // Une règle vide (champs clés absents) est ignorée
            if ($match === '' || $table === '' || $own === '') continue;
            $out[] = [
                'label'        => $label !== '' ? $label : $match,
                'match'        => $match,
                'id_source'    => in_array(($row['id_source'] ?? ''), ['end_of_path', 'query_param'], true) ? $row['id_source'] : 'end_of_path',
                'id_param'     => sanitize_key($row['id_param'] ?? ''),
                'table'        => $table,
                'id_column'    => self::safeIdent($row['id_column'] ?? 'ID') ?: 'ID',
                'owner_column' => $own,
                'staff_cap'    => sanitize_key($row['staff_cap'] ?? ''),
            ];
        }
        return $out;
    }
}
