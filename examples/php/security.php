<?php
/**
 * Fraudlogix API Security Implementation - All 6 Scenarios (PHP)
 */

// Configuration - Enable/disable scenarios as needed
$config = [
    'api_key' => getenv('FRAUDLOGIX_API_KEY') ?: 'YOUR_API_KEY_HERE',
    'blocked_page' => getenv('BLOCKED_PAGE') ?: 'https://yourdomain.com/blocked.html',
    'captcha_page' => getenv('CAPTCHA_PAGE') ?: 'https://yourdomain.com/verify.html',
    'scenarios' => [
        'block_high_extreme' => true,
        'quarantine_medium' => false,
        'strict_mode' => false,
        'block_proxies' => true,
        'block_anonymizers' => false,
        'geo_blocking' => true,
    ],
    'banned_countries' => ['CN', 'RU'],
];

function fraudlogixSecurityCheck($config) {
    $visitor_ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
    $risk_data = checkIPRisk($visitor_ip, $config['api_key']);
    if (!$risk_data) return; // Fail-open

    // Scenario 1
    if ($config['scenarios']['block_high_extreme'] && in_array($risk_data['RiskScore'] ?? '', ['High', 'Extreme'])) {
        header('Location: ' . $config['blocked_page']); exit();
    }

    // Scenario 2
    if ($config['scenarios']['quarantine_medium'] && ($risk_data['RiskScore'] ?? '') === 'Medium') {
        header('Location: ' . $config['captcha_page']); exit();
    }

    // Scenario 3
    if ($config['scenarios']['strict_mode'] && ($risk_data['RiskScore'] ?? '') !== 'Low' && !($risk_data['SearchEngineBot'] ?? false)) {
        header('Location: ' . $config['blocked_page']); exit();
    }

    // Scenario 4
    if ($config['scenarios']['block_proxies'] && ((bool)($risk_data['Proxy'] ?? false) || (bool)($risk_data['VPN'] ?? false) || (bool)($risk_data['TOR'] ?? false)) && !($risk_data['SearchEngineBot'] ?? false)) {
        header('Location: ' . $config['blocked_page']); exit();
    }

    // Scenario 5
    if ($config['scenarios']['block_anonymizers'] && (($risk_data['RiskScore'] ?? '') === 'Extreme' || (bool)($risk_data['Proxy'] ?? false) || (bool)($risk_data['VPN'] ?? false) || (bool)($risk_data['TOR'] ?? false))) {
        header('Location: ' . $config['blocked_page']); exit();
    }

    // Scenario 6
    if ($config['scenarios']['geo_blocking'] && in_array($risk_data['CountryCode'] ?? '', $config['banned_countries'])) {
        header('Location: ' . $config['blocked_page']); exit();
    }
}

function checkIPRisk($ip, $api_key) {
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, 'https://iplist.fraudlogix.com/v5?ip=' . urlencode($ip));
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, ['x-api-key: ' . $api_key]);
    curl_setopt($ch, CURLOPT_TIMEOUT, 5);
    $response = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    return ($code === 200) ? json_decode($response, true) : false;
}

// Demo usage
fraudlogixSecurityCheck($config);

echo 'Welcome! You have passed our security checks.';
