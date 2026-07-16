<?php
// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 WebTigers. Tiger™ and WebTigers™ are trademarks of WebTigers.
/**
 * TigerShield — the shipped request-WAF ruleset (v1). A CURATED, high-signal set — deliberately NOT a
 * ModSecurity-CRS port. The goal is near-zero false positives on a legit site: literal probe matches
 * (`strpos`) where possible, a few anchored regex where needed. Consumed by Tigershield_Service_Waf.
 *
 * Format: category-key => [
 *   'label'    => human name (shown in Live Traffic + the widget as "waf: <label>"),
 *   'tier'     => 'high' (may block, per waf.action) | 'soft' (SQLi/XSS heuristics — ALWAYS log-only),
 *   'in'       => which surface to match: 'path' | 'query' | 'pathquery' | 'ua' | 'method' | 'raw',
 *   'contains' => literal needles (case-matched to the surface: path/query/ua = lowercase, method = UPPER),
 *   'regex'    => anchored PCRE patterns (kept non-catastrophic; input is length-capped by the engine),
 * ]
 * Each category is an admin on/off toggle (tiger.tigershield.waf.cat.<key>). First match wins.
 */
return [

    // 1 — sensitive files / secret probes. No legit request asks for these on a Tiger site.
    'files' => [
        'label' => 'Sensitive file probe', 'tier' => 'high', 'in' => 'path',
        'contains' => [
            '/.env', '/.git/', '/.svn/', '/.hg/', '/.aws/', '/.ssh/', '/id_rsa', '/.htpasswd', '/.htaccess',
            '/wp-config.php', '/config.php.bak', '/configuration.php.bak', '/.bash_history', '/.ds_store',
            '/phpinfo.php', '/info.php', '/adminer.php', '/shell.php', '/backup.sql', '/dump.sql',
            '/database.sql', '/db.sql', '/vendor/phpunit/', '/server-status', '/.well-known/../',
        ],
    ],

    // 2 — WordPress / common-CMS probes. Tiger isn't WP, so /wp-* is ALWAYS a scan.
    'cms' => [
        'label' => 'CMS/plugin probe', 'tier' => 'high', 'in' => 'path',
        'contains' => ['/wp-login.php', '/wp-admin', '/xmlrpc.php', '/wp-content/', '/wp-includes/', '/wp-json/', '/wp-config'],
    ],

    // 3 — path traversal / LFI / PHP stream wrappers.
    'traversal' => [
        'label' => 'Path traversal / LFI', 'tier' => 'high', 'in' => 'pathquery',
        'contains' => ['/etc/passwd', '/etc/shadow', '/proc/self/environ', 'php://', 'file://', 'data://', 'expect://', 'phar://', 'zip://'],
        'regex'    => ['~\.\.[/\\\\]~', '~%2e%2e(?:%2f|%5c|/|\\\\)~i'],
    ],

    // 4 — command / code injection.
    'rce' => [
        'label' => 'Command injection', 'tier' => 'high', 'in' => 'query',
        'regex' => [
            '~\b(?:system|exec|passthru|shell_exec|popen|proc_open|pcntl_exec)\s*\(~i',
            '~[;|&`]\s*(?:wget|curl|nc|ncat|bash|sh|python|perl|cat|chmod|rm)\b~i',
            '~\$\((?:[^)]|$)~',
        ],
    ],

    // 5 — null bytes / control chars (raw, undecoded surface).
    'nullbyte' => [
        'label' => 'Null byte / control char', 'tier' => 'high', 'in' => 'raw',
        'contains' => ['%00'],
        'regex'    => ['~[\x00-\x08\x0e-\x1f]~'],
    ],

    // 6 — disallowed / dangerous HTTP methods.
    'method' => [
        'label' => 'Disallowed method', 'tier' => 'high', 'in' => 'method',
        'contains' => ['TRACE', 'TRACK', 'CONNECT', 'DEBUG'],
    ],

    // 7 — known scanner / attack-tool user-agents.
    'scanners' => [
        'label' => 'Scanner tool', 'tier' => 'high', 'in' => 'ua',
        'contains' => [
            'sqlmap', 'nikto', 'nmap', 'masscan', 'nuclei', 'acunetix', 'nessus', 'openvas', 'dirbuster',
            'gobuster', 'wpscan', 'zmeu', 'sqlninja', 'arachni', 'w3af', 'jorgee', 'fimap', 'havij', 'netsparker',
        ],
    ],

    // 8 — SQL injection heuristics. SOFT: always log-only (a legit search may contain these words).
    'sqli' => [
        'label' => 'SQL injection heuristic', 'tier' => 'soft', 'in' => 'query',
        'regex' => [
            '~\bunion\s+(?:all\s+)?select\b~i',
            '~\b(?:sleep|benchmark|pg_sleep|waitfor\s+delay)\s*\(~i',
            '~\binformation_schema\b~i',
            '~\bxp_cmdshell\b~i',
            '~;\s*drop\s+table\b~i',
            '~(?:\'|")\s*(?:or|and)\s+(?:\'|")?\d+(?:\'|")?\s*=\s*(?:\'|")?\d+~i',
        ],
    ],

    // 9 — reflected-XSS heuristics. SOFT: always log-only.
    'xss' => [
        'label' => 'XSS heuristic', 'tier' => 'soft', 'in' => 'query',
        'regex' => [
            '~<script\b~i',
            '~javascript:~i',
            '~\bon(?:error|load|click|mouseover|focus)\s*=~i',
            '~<iframe\b~i',
            '~<svg[^>]*\bon\w+\s*=~i',
        ],
    ],

];
