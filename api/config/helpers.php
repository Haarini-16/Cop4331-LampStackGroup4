<?php
// ============================================================
//  api/config/helpers.php — Utility & Helper Functions for API
// ============================================================

/**
 * Loads environment variables from a .env file into putenv, $_ENV, and $_SERVER.
 *
 * @param string|null $path Path to the .env file
 */
function loadEnv($path = null) {
    static $loaded = false;
    if ($loaded) {
        return;
    }

    if ($path === null) {
        $possiblePaths = [
            __DIR__ . '/../../.env',
            __DIR__ . '/../.env',
            __DIR__ . '/.env',
            (defined('ROOT_PATH') ? ROOT_PATH . '/.env' : null),
        ];
        foreach ($possiblePaths as $p) {
            if ($p && file_exists($p)) {
                $path = $p;
                break;
            }
        }
    }

    if ($path && file_exists($path)) {
        $lines = file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        foreach ($lines as $line) {
            $line = trim($line);
            if (empty($line) || str_starts_with($line, '#')) {
                continue;
            }
            if (strpos($line, '=') !== false) {
                list($name, $value) = explode('=', $line, 2);
                $name  = trim($name);
                $value = trim($value);

                // Strip surrounding quotes
                if ((str_starts_with($value, '"') && str_ends_with($value, '"')) ||
                    (str_starts_with($value, "'") && str_ends_with($value, "'"))) {
                    $value = substr($value, 1, -1);
                }

                if (getenv($name) === false) {
                    putenv("{$name}={$value}");
                    $_ENV[$name] = $value;
                    $_SERVER[$name] = $value;
                }
            }
        }
    }
    $loaded = true;
}

// Automatically load environment variables
loadEnv();

/**
 * Sets standard CORS headers to allow cross-origin API requests.
 * Handles preflight OPTIONS requests by exiting with 200 OK.
 */
function setCORSHeaders() {
    header("Access-Control-Allow-Origin: *");
    header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS");
    header("Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With, X-User-Id");

    if (isset($_SERVER['REQUEST_METHOD']) && $_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
        http_response_code(200);
        exit;
    }
}

/**
 * Sends a JSON response with the specified HTTP status code and terminates execution.
 *
 * @param int $statusCode HTTP status code (e.g. 200, 201, 400, 404, 405, 500)
 * @param mixed $data Data array or object to serialize as JSON
 */
function respond($statusCode, $data) {
    http_response_code($statusCode);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($data);
    exit;
}

//Read the JSON object sent by the frontend or Bruno
function getRequestBody() {
    static $body = null;
    if ($body !== null) return $body;
    $type = strtolower(trim(explode(';', $_SERVER['CONTENT_TYPE'] ?? '')[0]));
    if ($type !== 'application/json') respond(415, ['error' => 'Send Content-Type: application/json']);
    $decoded = json_decode(file_get_contents('php://input'));
    if (!is_object($decoded)) respond(400, ['error' => 'Send a valid JSON object']);
    $body = (array) $decoded;
    return $body;
}

//Only accept the user ID saved by a successful login
function requireAuth() {
    $userId = $_SESSION['userId'] ?? null;
    if (!is_int($userId) || $userId < 1) respond(401, ['error' => 'Please log in first']);
    return $userId;
}

//Check text before sending it to a database column
function textField($body, $key, $max, $required = true) {
    $value = $body[$key] ?? '';
    if (!is_string($value)) respond(400, ['error' => "$key must be text"]);
    $value = trim($value);
    if ($required && $value === '') respond(400, ['error' => "$key is required"]);
    if (strlen($value) > $max) respond(400, ['error' => "$key must be $max bytes or fewer"]);
    return $value;
}

//Check the password without trimming it, then let PHP hash and salt it
function hashNewPassword($body) {
    $password = $body['password'] ?? '';
    if (!is_string($password) || $password === '' || strlen($password) > 72 || strpos($password, "\0") !== false) {
        respond(400, ['error' => 'Password must contain 1–72 bytes and no null bytes']);
    }
    return password_hash($password, PASSWORD_BCRYPT);
}

//Read a positive ID from the URL for the record we want to change
function requestId($key = 'id') {
    $id = filter_var($_GET[$key] ?? null, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]);
    if (!$id) respond(400, ['error' => "A valid $key is required"]);
    return $id;
}

//Use the same four contact fields for adding and editing
function contactFields($body) {
    $first = textField($body, 'firstName', 50);
    $last = textField($body, 'lastName', 50);
    $email = textField($body, 'email', 100, false);
    $phone = textField($body, 'phoneNumber', 20, false);
    if ($email !== '' && !filter_var($email, FILTER_VALIDATE_EMAIL)) respond(400, ['error' => 'Enter a valid email address']);
    return [$first, $last, $email, $phone];
}
