<?php
/**
 * ══════════════════════════════════════════════════════════════
 *  WafCore\BodyScanner — Analyseur structurel de payload (port PHP)
 * ══════════════════════════════════════════════════════════════
 *
 * Port fidèle de core/body-scanner.ts. PORTABLE : aucune dépendance
 * WordPress/Laravel/framework. PHP 8.0+.
 *
 * Détecte dans un payload déjà décodé (array PHP issu de json_decode) :
 *   - Prototype Pollution     (__proto__, constructor, prototype)
 *   - RCE / désérialisation    (system, exec, eval, gadgets PHP/Node)
 *   - SSRF dans les valeurs    (IP internes, cloud metadata, schémas)
 *   - DoS structurel           (profondeur, explosion clés/tableaux, strings géantes)
 *
 * Usage (ex. WordPress, hook rest_pre_dispatch) :
 *   $verdict = \WafCore\BodyScanner::scan($decoded_json);
 *   if (!$verdict['safe']) { wp_send_json_error('Requête invalide', 400); }
 * ══════════════════════════════════════════════════════════════
 */

namespace WafCore;

final class BodyScanner
{
    /** @var array<string,mixed> options par défaut */
    public const DEFAULTS = [
        'maxDepth'                 => 24,
        'maxKeys'                  => 5000,
        'maxArrayLength'           => 10000,
        'maxStringLength'          => 50000,
        'checkPrototypePollution'  => true,
        'checkRce'                 => true,
        'checkSsrf'                => true,
    ];

    /** Clés de pollution de prototype / objet. */
    private const POLLUTION_KEYS = ['__proto__', 'prototype', 'constructor'];

    /** Signatures RCE / désérialisation (Node + PHP). */
    private const RCE_SIGNATURES = [
        ['/\bchild_process\b/i',                        'child_process',          95],
        ['/\bprocess\.(?:mainModule|binding|env)\b/i',  'process internals',      95],
        ['/\brequire\s*\(\s*[\'"`]/i',                   'require() call',         90],
        ['/\b(?:eval|assert|system|exec|shell_exec|passthru|popen|proc_open)\s*\(/i', 'php/node code exec', 92],
        ['/\b_\$\$ND_FUNC\$\$_/',                        'node-serialize gadget',  98],
        ['/O:\d+:"[^"]+":\d+:\{/',                       'php object injection',   90], // serialize() gadget
        ['/\{\{.*(?:constructor|process|require|global|system).*\}\}/i', 'SSTI gadget', 90],
        ['/\$\{.*(?:process|require|global).*\}/i',      'template injection',     85],
    ];

    private const DANGEROUS_SCHEMES = '/\b(?:gopher|dict|file|ldap|ftp|jar|netdoc):\/\//i';

    private const CLOUD_METADATA = [
        '169.254.169.254', 'metadata.google.internal', '100.100.200.200', 'metadata',
    ];

    /**
     * Teste si un hôte cible une ressource interne (parsing d'octets correct).
     */
    public static function isInternalHost(string $host): bool
    {
        $h = strtolower(trim(preg_replace('/:\d+$/', '', $host)));

        if ($h === 'localhost' || str_ends_with($h, '.localhost') || $h === '0.0.0.0') return true;
        if ($h === '[::1]' || $h === '::1') return true;
        if (str_starts_with($h, '[fc') || str_starts_with($h, '[fd') || str_starts_with($h, '[fe80')) return true;
        if (in_array($h, self::CLOUD_METADATA, true)) return true;

        if (preg_match('/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/', $h, $m)) {
            $a = (int)$m[1]; $b = (int)$m[2];
            if ($a > 255 || $b > 255 || (int)$m[3] > 255 || (int)$m[4] > 255) return false;
            if ($a === 127) return true;                       // loopback
            if ($a === 10) return true;                        // 10/8
            if ($a === 192 && $b === 168) return true;         // 192.168/16
            if ($a === 172 && $b >= 16 && $b <= 31) return true; // 172.16/12 (pas tout 172.x)
            if ($a === 169 && $b === 254) return true;         // link-local + IMDS
            if ($a === 100 && $b >= 64 && $b <= 127) return true; // CGNAT
            if ($a === 0) return true;
        }
        return false;
    }

    /**
     * Analyse un payload décodé. Ne lève jamais.
     *
     * @param mixed $payload
     * @param array<string,mixed> $options
     * @return array{safe:bool,threat:?string,confidence:int,path:string,detail:string}
     */
    public static function scan(mixed $payload, array $options = []): array
    {
        $o = array_merge(self::DEFAULTS, $options);
        $safe = ['safe' => true, 'threat' => null, 'confidence' => 0, 'path' => '', 'detail' => ''];

        if ($payload === null) return $safe;
        if (!is_array($payload) && !is_string($payload) && !is_object($payload)) return $safe;

        $keyCount = 0;
        // Pile explicite (anti récursion profonde hostile)
        $stack = [['node' => $payload, 'depth' => 0, 'path' => '']];

        while (!empty($stack)) {
            $frame = array_pop($stack);
            $node = $frame['node']; $depth = $frame['depth']; $path = $frame['path'];

            if ($depth > $o['maxDepth']) {
                return self::threat('recursive_depth', 80, $path, "Profondeur > {$o['maxDepth']} — possible DoS JSON");
            }

            if (is_string($node)) {
                $v = self::scanString($node, $path !== '' ? $path : '(racine)', $o);
                if ($v !== null) return $v;
                continue;
            }

            if (is_object($node)) $node = (array)$node;
            if (!is_array($node)) continue;

            // Tableau séquentiel
            if (array_is_list($node)) {
                if (count($node) > $o['maxArrayLength']) {
                    return self::threat('array_explosion', 75, $path, count($node) . " éléments — possible DoS");
                }
                foreach ($node as $i => $child) {
                    $stack[] = ['node' => $child, 'depth' => $depth + 1, 'path' => "{$path}[{$i}]"];
                }
                continue;
            }

            // Objet associatif → clés (pollution) + descente
            foreach ($node as $key => $child) {
                $keyCount++;
                if ($keyCount > $o['maxKeys']) {
                    return self::threat('key_explosion', 75, $path, "Plus de {$o['maxKeys']} clés — possible DoS");
                }
                if ($o['checkPrototypePollution'] && in_array((string)$key, self::POLLUTION_KEYS, true)) {
                    return self::threat('prototype_pollution', 98, $path !== '' ? "{$path}.{$key}" : (string)$key,
                        "Clé de pollution de prototype \"{$key}\"");
                }
                $childPath = $path !== '' ? "{$path}.{$key}" : (string)$key;
                $stack[] = ['node' => $child, 'depth' => $depth + 1, 'path' => $childPath];
            }
        }

        return $safe;
    }

    /** @return array{safe:bool,threat:string,confidence:int,path:string,detail:string} */
    private static function threat(string $threat, int $confidence, string $path, string $detail): array
    {
        return ['safe' => false, 'threat' => $threat, 'confidence' => $confidence, 'path' => $path, 'detail' => $detail];
    }

    /** @return array{safe:bool,threat:string,confidence:int,path:string,detail:string}|null */
    private static function scanString(string $value, string $path, array $o): ?array
    {
        if (strlen($value) > $o['maxStringLength']) {
            return self::threat('oversized_string', 70, $path, "Chaîne de " . strlen($value) . " caractères — possible DoS/ReDoS");
        }

        if ($o['checkRce']) {
            foreach (self::RCE_SIGNATURES as [$re, $label, $conf]) {
                if (preg_match($re, $value)) {
                    return self::threat('rce_gadget', $conf, $path, "Gadget RCE [{$label}] dans {$path}");
                }
            }
        }

        if ($o['checkSsrf']) {
            if (preg_match(self::DANGEROUS_SCHEMES, $value)) {
                return self::threat('ssrf_internal_target', 85, $path, "Schéma d'URL dangereux dans {$path}");
            }
            if (preg_match_all('/\b(?:https?|ftp|gopher|file|dict|ldap):\/\/([^\s\/?#"\']+)/i', $value, $matches)) {
                foreach ($matches[1] as $hostCandidate) {
                    if (self::isInternalHost($hostCandidate)) {
                        return self::threat('ssrf_internal_target', 92, $path, "Cible interne/cloud-metadata \"{$hostCandidate}\" dans {$path}");
                    }
                }
            }
        }

        return null;
    }
}
