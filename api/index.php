<?php
//Contacts API: sign in, manage your contacts, and handle admin actions
require_once __DIR__ . '/config/db.php';
require_once __DIR__ . '/config/helpers.php';

setCORSHeaders();

//Remember the user between requests with an HTTPS-only session cookie
ini_set('session.use_strict_mode', '1');
session_set_cookie_params([
    'path' => '/',
    'secure' => true,
    'httponly' => true,
    'samesite' => 'Lax'
]);
session_start();

$method = $_SERVER['REQUEST_METHOD'];
$action = $_GET['action'] ?? '';
if (!is_string($action)) respond(400, ['error' => 'Invalid action']);
$db = getDB();

//Check that the API and database can respond
if ($method === 'GET' && (isset($_GET['ping']) || $action === 'ping')) {
    respond(200, ['status' => 'OK', 'timestamp' => time()]);
}

try {
    //Create a regular account and store a password hash instead of the password
    if ($method === 'POST' && $action === 'signup') {
        $body = getRequestBody();
        $firstName = textField($body, 'firstName', 50);
        $lastName = textField($body, 'lastName', 50);
        $login = textField($body, 'login', 50);
        $hash = hashNewPassword($body);
        $stmt = $db->prepare("INSERT INTO Users (FirstName, LastName, Username, Password, role, status) VALUES (?, ?, ?, ?, 'user', 'active')");
        $stmt->execute([$firstName, $lastName, $login, $hash]);
        respond(201, ['message' => 'Account created']);
    }

    //Check the password and account status before remembering who logged in
    if ($method === 'POST' && ($action === '' || $action === 'login')) {
        $body = getRequestBody();
        if ($action === 'login' || array_key_exists('login', $body) || array_key_exists('password', $body)) {
            unset($_SESSION['userId']);
            $login = textField($body, 'login', 50);
            $password = $body['password'] ?? '';
            if (!is_string($password) || $password === '') {
                respond(400, ['error' => 'Login and password are required']);
            }
            $stmt = $db->prepare('SELECT ID, FirstName, LastName, Password, role, status FROM Users WHERE Username = ? LIMIT 1');
            $stmt->execute([$login]);
            $user = $stmt->fetch();
            if (!$user || !password_verify($password, $user['Password'])) {
                respond(401, ['id' => 0, 'firstName' => '', 'lastName' => '', 'error' => 'No Records Found']);
            }
            if ($user['status'] !== 'active') respond(403, ['error' => 'This account is disabled']);
            session_regenerate_id(true);
            $_SESSION['userId'] = (int) $user['ID'];
            respond(200, [
                'id' => (int) $user['ID'],
                'firstName' => $user['FirstName'],
                'lastName' => $user['LastName'],
                'role' => $user['role'],
                'error' => ''
            ]);
        }
    }

    //Clear the login when the user signs out
    if ($method === 'POST' && $action === 'logout') {
        $_SESSION = [];
        session_destroy();
        setcookie(session_name(), '', ['expires' => time() - 3600, 'path' => '/', 'secure' => true, 'httponly' => true, 'samesite' => 'Lax']);
        respond(200, ['message' => 'Logged out']);
    }

    //Recheck the saved account so disabling it also stops an existing session
    $userId = requireAuth();
    $stmt = $db->prepare('SELECT ID AS id, FirstName AS firstName, LastName AS lastName, role, status FROM Users WHERE ID = ?');
    $stmt->execute([$userId]);
    $currentUser = $stmt->fetch();
    if (!$currentUser || $currentUser['status'] !== 'active') {
        unset($_SESSION['userId']);
        respond(401, ['error' => 'Please log in with an active account']);
    }
    if ($method === 'GET' && $action === 'me') respond(200, $currentUser);

    //Search through SQL and return one page instead of loading every record
    $search = textField($_GET, 'q', 100, false);
    $page = filter_var($_GET['page'] ?? 1, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1, 'max_range' => 1000000]]);
    if (!$page) respond(400, ['error' => 'Page must be a positive integer']);
    $offset = ($page - 1) * 20;
    $like = '%' . $search . '%';
    $contactColumns = 'ID AS id, FirstName AS firstName, LastName AS lastName, Email AS email, PhoneNumber AS phoneNumber';

    //Only an active admin can use the admin routes
    if (str_starts_with($action, 'admin-')) {
        if ($currentUser['role'] !== 'admin') respond(403, ['error' => 'Administrator access required']);

        //Find users without returning their password hashes
        if ($action === 'admin-users' && $method === 'GET') {
            $stmt = $db->prepare("SELECT ID AS id, FirstName AS firstName, LastName AS lastName, Username AS login, role, status FROM Users WHERE CONCAT_WS(' ', FirstName, LastName, Username) LIKE ? ORDER BY ID LIMIT 20 OFFSET $offset");
            $stmt->execute([$like]);
            respond(200, ['users' => $stmt->fetchAll(), 'page' => $page]);
        }

        //Let an admin search contacts for a selected user or across all users
        if ($action === 'admin-contacts' && $method === 'GET') {
            $owner = isset($_GET['userId']) ? requestId('userId') : null;
            $where = $owner === null ? '' : 'UserID = ? AND ';
            $params = $owner === null ? [$like] : [$owner, $like];
            $stmt = $db->prepare("SELECT $contactColumns, UserID AS userId FROM Contacts WHERE $where CONCAT_WS(' ', FirstName, LastName, Email, PhoneNumber) LIKE ? ORDER BY ID LIMIT 20 OFFSET $offset");
            $stmt->execute($params);
            respond(200, ['contacts' => $stmt->fetchAll(), 'page' => $page]);
        }

        //Create another admin using the same name and password checks as signup
        if ($action === 'admin-create' && $method === 'POST') {
            $body = getRequestBody();
            $firstName = textField($body, 'firstName', 50);
            $lastName = textField($body, 'lastName', 50);
            $login = textField($body, 'login', 50);
            $hash = hashNewPassword($body);
            $stmt = $db->prepare("INSERT INTO Users (FirstName, LastName, Username, Password, role, status) VALUES (?, ?, ?, ?, 'admin', 'active')");
            $stmt->execute([$firstName, $lastName, $login, $hash]);
            respond(201, ['id' => (int) $db->lastInsertId(), 'message' => 'Admin created']);
        }

        //Disable or reactivate an account without deleting it, including admin accounts
        if ($action === 'admin-status' && $method === 'PUT') {
            $id = requestId();
            $body = getRequestBody();
            $status = $body['status'] ?? '';
            if (!in_array($status, ['active', 'disabled'], true)) respond(400, ['error' => 'Status must be active or disabled']);
            $stmt = $db->prepare('SELECT ID FROM Users WHERE ID = ?');
            $stmt->execute([$id]);
            if (!$stmt->fetch()) respond(404, ['error' => 'User not found']);
            $stmt = $db->prepare('UPDATE Users SET status = ? WHERE ID = ?');
            $stmt->execute([$status, $id]);
            respond(200, ['message' => 'Account status updated']);
        }

        //Replace the selected account password with a new hash
        if ($action === 'admin-password' && $method === 'PUT') {
            $id = requestId();
            $hash = hashNewPassword(getRequestBody());
            $stmt = $db->prepare('SELECT ID FROM Users WHERE ID = ?');
            $stmt->execute([$id]);
            if (!$stmt->fetch()) respond(404, ['error' => 'User not found']);
            $stmt = $db->prepare('UPDATE Users SET Password = ? WHERE ID = ?');
            $stmt->execute([$hash, $id]);
            respond(200, ['message' => 'Password updated']);
        }
        respond(405, ['error' => 'Unsupported admin action or method']);
    }

    if ($action !== '' && $action !== 'contacts') respond(404, ['error' => 'Unknown action']);
    switch ($method) {
        //List or search only the contacts belonging to the logged-in user
        case 'GET':
            $stmt = $db->prepare("SELECT $contactColumns FROM Contacts WHERE UserID = ? AND CONCAT_WS(' ', FirstName, LastName, Email, PhoneNumber) LIKE ? ORDER BY LastName, FirstName, ID LIMIT 20 OFFSET $offset");
            $stmt->execute([$userId, $like]);
            respond(200, ['contacts' => $stmt->fetchAll(), 'page' => $page]);
            break;

        //Add a contact and attach it to the session user, not an ID from the browser
        case 'POST':
            $contact = contactFields(getRequestBody());
            $stmt = $db->prepare('INSERT INTO Contacts (FirstName, LastName, Email, PhoneNumber, UserID) VALUES (?, ?, ?, ?, ?)');
            $stmt->execute([...$contact, $userId]);
            respond(201, ['id' => (int) $db->lastInsertId(), 'message' => 'Contact created']);
            break;

        //Update the four editable fields after checking that the contact belongs to this user
        case 'PUT':
            $id = requestId();
            $contact = contactFields(getRequestBody());
            $stmt = $db->prepare('SELECT ID FROM Contacts WHERE ID = ? AND UserID = ?');
            $stmt->execute([$id, $userId]);
            if (!$stmt->fetch()) respond(404, ['error' => 'Contact not found']);
            $stmt = $db->prepare('UPDATE Contacts SET FirstName = ?, LastName = ?, Email = ?, PhoneNumber = ? WHERE ID = ? AND UserID = ?');
            $stmt->execute([...$contact, $id, $userId]);
            respond(200, ['message' => 'Contact updated']);
            break;

        //Delete just the selected contact owned by this user
        case 'DELETE':
            $stmt = $db->prepare('DELETE FROM Contacts WHERE ID = ? AND UserID = ?');
            $stmt->execute([requestId(), $userId]);
            if (!$stmt->rowCount()) respond(404, ['error' => 'Contact not found']);
            respond(200, ['message' => 'Contact deleted']);
            break;

        default:
            respond(405, ['error' => 'Method not allowed']);
    }
} catch (PDOException $e) {
    //Return a readable error without exposing database details
    if (($e->errorInfo[1] ?? null) === 1062) respond(409, ['error' => 'Username already exists']);
    error_log($e->getMessage());
    respond(500, ['error' => 'Could not complete request']);
}
