<?php
//Run from the terminal once to create the required root account without replacing anyone
if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}
require_once __DIR__ . '/db.php';
$db = getDB();
$stmt = $db->prepare('SELECT ID FROM Users WHERE Username = ?');
$stmt->execute(['root']);
if ($stmt->fetch()) {
    fwrite(STDOUT, "Root already exists; nothing changed.\n");
    exit;
}
$password = rtrim(stream_get_contents(STDIN), "\r\n");
if ($password === '' || strlen($password) > 72 || strpos($password, "\0") !== false) {
    fwrite(STDERR, "Supply a password of 1–72 bytes through standard input.\n");
    exit(1);
}
$stmt = $db->prepare("INSERT INTO Users (FirstName, LastName, Username, Password, role, status) VALUES ('Application', 'Administrator', 'root', ?, 'admin', 'active')");
$stmt->execute([password_hash($password, PASSWORD_BCRYPT)]);
fwrite(STDOUT, "Created root (Application Administrator).\n");
