<?php
// ============================================
// FILE: index.php
// Vulnerable PHP Application with SQL Injection
// ============================================

// Database configuration
$host = 'localhost';
$dbname = 'testdb';
$username = 'root';
$password = 'password';

// Create connection (vulnerable - uses old mysql extension)
$conn = mysqli_connect($host, $username, $password, $dbname);

// Check connection
if (!$conn) {
    die("Connection failed: " . mysqli_connect_error());
}

// ============================================
// VULNERABILITY 1: Basic SQL Injection
// in Login Form
// ============================================

function loginUser($username, $password) {
    global $conn;
    
    // VULNERABLE: Direct string concatenation
    $sql = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
    
    // VULNERABLE: Using mysql_query (deprecated)
    $result = mysqli_query($conn, $sql);
    
    if ($result && mysqli_num_rows($result) > 0) {
        return mysqli_fetch_assoc($result);
    }
    return false;
}

// ============================================
// VULNERABILITY 2: SQL Injection in Search
// ============================================

function searchUsers($searchTerm) {
    global $conn;
    
    // VULNERABLE: No sanitization
    $sql = "SELECT * FROM users WHERE username LIKE '%$searchTerm%' OR email LIKE '%$searchTerm%'";
    
    // VULNERABLE: Using mysqli_query with unsafe query
    $result = mysqli_query($conn, $sql);
    
    $users = [];
    if ($result) {
        while ($row = mysqli_fetch_assoc($result)) {
            $users[] = $row;
        }
    }
    return $users;
}

// ============================================
// VULNERABILITY 3: SQL Injection in GET Parameter
// ============================================

function getUserById($id) {
    global $conn;
    
    // VULNERABLE: Unsafe use of GET parameter
    $sql = "SELECT * FROM users WHERE id = $id";
    
    // VULNERABLE: Using mysqli_query
    $result = mysqli_query($conn, $sql);
    
    if ($result && mysqli_num_rows($result) > 0) {
        return mysqli_fetch_assoc($result);
    }
    return null;
}

// ============================================
// VULNERABILITY 4: SQL Injection with
// Multiple Parameters
// ============================================

function getUsersByFilter($name, $email, $role) {
    global $conn;
    
    // VULNERABLE: Building query with multiple concatenations
    $sql = "SELECT * FROM users WHERE 1=1";
    
    if (!empty($name)) {
        $sql .= " AND username = '$name'";
    }
    if (!empty($email)) {
        $sql .= " AND email = '$email'";
    }
    if (!empty($role)) {
        $sql .= " AND role = '$role'";
    }
    
    // VULNERABLE: Using mysqli_query
    $result = mysqli_query($conn, $sql);
    
    $users = [];
    if ($result) {
        while ($row = mysqli_fetch_assoc($result)) {
            $users[] = $row;
        }
    }
    return $users;
}

// ============================================
// VULNERABILITY 5: SQL Injection in ORDER BY
// ============================================

function getUsersSorted($sortBy, $order) {
    global $conn;
    
    // VULNERABLE: Direct concatenation in ORDER BY
    $sql = "SELECT * FROM users ORDER BY $sortBy $order";
    
    // VULNERABLE: Using mysqli_query
    $result = mysqli_query($conn, $sql);
    
    $users = [];
    if ($result) {
        while ($row = mysqli_fetch_assoc($result)) {
            $users[] = $row;
        }
    }
    return $users;
}

// ============================================
// VULNERABILITY 6: SQL Injection in LIKE clause
// ============================================

function searchProducts($keyword) {
    global $conn;
    
    // VULNERABLE: Using LIKE with unsanitized input
    $sql = "SELECT * FROM products WHERE name LIKE '%$keyword%' OR description LIKE '%$keyword%'";
    
    // VULNERABLE: Using mysqli_query
    $result = mysqli_query($conn, $sql);
    
    $products = [];
    if ($result) {
        while ($row = mysqli_fetch_assoc($result)) {
            $products[] = $row;
        }
    }
    return $products;
}

// ============================================
// VULNERABILITY 7: SQL Injection in INSERT
// ============================================

function createUser($username, $email, $password, $role) {
    global $conn;
    
    // VULNERABLE: Direct concatenation in INSERT
    $sql = "INSERT INTO users (username, email, password, role) 
            VALUES ('$username', '$email', '$password', '$role')";
    
    // VULNERABLE: Using mysqli_query
    if (mysqli_query($conn, $sql)) {
        return mysqli_insert_id($conn);
    }
    return false;
}

// ============================================
// VULNERABILITY 8: SQL Injection in UPDATE
// ============================================

function updateUser($id, $username, $email, $role) {
    global $conn;
    
    // VULNERABLE: Direct concatenation in UPDATE
    $sql = "UPDATE users SET username = '$username', email = '$email', role = '$role' WHERE id = $id";
    
    // VULNERABLE: Using mysqli_query
    return mysqli_query($conn, $sql);
}

// ============================================
// VULNERABILITY 9: SQL Injection in DELETE
// ============================================

function deleteUser($id) {
    global $conn;
    
    // VULNERABLE: Direct concatenation in DELETE
    $sql = "DELETE FROM users WHERE id = $id";
    
    // VULNERABLE: Using mysqli_query
    return mysqli_query($conn, $sql);
}

// ============================================
// VULNERABILITY 10: SQL Injection with
// Dynamic Table Names
// ============================================

function getDataFromTable($table, $id) {
    global $conn;
    
    // VULNERABLE: Direct concatenation of table name
    $sql = "SELECT * FROM $table WHERE id = $id";
    
    // VULNERABLE: Using mysqli_query
    $result = mysqli_query($conn, $sql);
    
    if ($result && mysqli_num_rows($result) > 0) {
        return mysqli_fetch_assoc($result);
    }
    return null;
}

// ============================================
// VULNERABILITY 11: SQL Injection in
// Stored Procedure Call
// ============================================

function callStoredProcedure($param) {
    global $conn;
    
    // VULNERABLE: Using unsanitized input in procedure call
    $sql = "CALL get_user_by_name('$param')";
    
    // VULNERABLE: Using mysqli_query
    $result = mysqli_query($conn, $sql);
    
    if ($result && mysqli_num_rows($result) > 0) {
        return mysqli_fetch_assoc($result);
    }
    return null;
}

// ============================================
// VULNERABILITY 12: SQL Injection with
// Multiple Statements
// ============================================

function getUsersMultiple($ids) {
    global $conn;
    
    // VULNERABLE: Multiple statements in one query
    $sql = "SELECT * FROM users WHERE id IN ($ids); DELETE FROM logs WHERE user_id IN ($ids)";
    
    // VULNERABLE: Using multi_query
    if (mysqli_multi_query($conn, $sql)) {
        $result = mysqli_store_result($conn);
        if ($result && mysqli_num_rows($result) > 0) {
            return mysqli_fetch_assoc($result);
        }
    }
    return null;
}

// ============================================
// VULNERABILITY 13: SQL Injection using
// HTTP Headers
// ============================================

function getUserByUserAgent() {
    global $conn;
    
    // VULNERABLE: Using HTTP header directly in SQL
    $userAgent = $_SERVER['HTTP_USER_AGENT'];
    $sql = "INSERT INTO user_agents (user_agent) VALUES ('$userAgent')";
    
    // VULNERABLE: Using mysqli_query
    return mysqli_query($conn, $sql);
}

// ============================================
// VULNERABILITY 14: SQL Injection in
// Cookie Values
// ============================================

function getUserByCookie() {
    global $conn;
    
    // VULNERABLE: Using cookie value directly in SQL
    $sessionId = $_COOKIE['session_id'];
    $sql = "SELECT * FROM sessions WHERE session_id = '$sessionId'";
    
    // VULNERABLE: Using mysqli_query
    $result = mysqli_query($conn, $sql);
    
    if ($result && mysqli_num_rows($result) > 0) {
        return mysqli_fetch_assoc($result);
    }
    return null;
}

// ============================================
// VULNERABILITY 15: SQL Injection using
// JSON Parameters
// ============================================

function searchFromJson($jsonData) {
    global $conn;
    
    // VULNERABLE: Parsing JSON without sanitization
    $data = json_decode($jsonData, true);
    $field = $data['field'] ?? 'username';
    $value = $data['value'] ?? '';
    
    $sql = "SELECT * FROM users WHERE $field = '$value'";
    
    // VULNERABLE: Using mysqli_query
    $result = mysqli_query($conn, $sql);
    
    if ($result && mysqli_num_rows($result) > 0) {
        return mysqli_fetch_assoc($result);
    }
    return null;
}

// ============================================
// VULNERABILITY 16: SQL Injection with
// Regex Pattern
// ============================================

function searchWithRegex($pattern) {
    global $conn;
    
    // VULNERABLE: Using regex with unsanitized input
    $sql = "SELECT * FROM users WHERE username REGEXP '$pattern'";
    
    // VULNERABLE: Using mysqli_query
    $result = mysqli_query($conn, $sql);
    
    $users = [];
    if ($result) {
        while ($row = mysqli_fetch_assoc($result)) {
            $users[] = $row;
        }
    }
    return $users;
}

// ============================================
// VULNERABILITY 17: SQL Injection in
// File Upload Handler
// ============================================

function handleFileUpload($filename, $user_id) {
    global $conn;
    
    // VULNERABLE: Using filename in SQL
    $sql = "INSERT INTO files (filename, user_id) VALUES ('$filename', $user_id)";
    
    // VULNERABLE: Using mysqli_query
    return mysqli_query($conn, $sql);
}

// ============================================
// VULNERABILITY 18: SQL Injection with
// Server Variables
// ============================================

function getUserByIP() {
    global $conn;
    
    // VULNERABLE: Using server variable in SQL
    $ip = $_SERVER['REMOTE_ADDR'];
    $sql = "SELECT * FROM access_logs WHERE ip_address = '$ip'";
    
    // VULNERABLE: Using mysqli_query
    $result = mysqli_query($conn, $sql);
    
    if ($result && mysqli_num_rows($result) > 0) {
        return mysqli_fetch_assoc($result);
    }
    return null;
}

// ============================================
// VULNERABILITY 19: SQL Injection in
// Dynamic Column Names
// ============================================

function getUsersByColumn($column, $value) {
    global $conn;
    
    // VULNERABLE: Dynamic column name
    $sql = "SELECT * FROM users WHERE $column = '$value'";
    
    // VULNERABLE: Using mysqli_query
    $result = mysqli_query($conn, $sql);
    
    if ($result && mysqli_num_rows($result) > 0) {
        return mysqli_fetch_assoc($result);
    }
    return null;
}

// ============================================
// VULNERABILITY 20: SQL Injection in
// Group By and Having
// ============================================

function getAggregatedData($groupBy, $having) {
    global $conn;
    
    // VULNERABLE: Dynamic GROUP BY and HAVING
    $sql = "SELECT role, COUNT(*) as count 
            FROM users 
            GROUP BY $groupBy 
            HAVING $having";
    
    // VULNERABLE: Using mysqli_query
    $result = mysqli_query($conn, $sql);
    
    $data = [];
    if ($result) {
        while ($row = mysqli_fetch_assoc($result)) {
            $data[] = $row;
        }
    }
    return $data;
}

// ============================================
// Main Application Logic
// ============================================

// Handle form submissions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['login'])) {
        // VULNERABLE: Login
        $username = $_POST['username'];
        $password = $_POST['password'];
        $user = loginUser($username, $password);
        
        if ($user) {
            echo "Login successful! Welcome " . htmlspecialchars($user['username']);
        } else {
            echo "Login failed!";
        }
    }
    
    if (isset($_POST['search'])) {
        // VULNERABLE: Search
        $term = $_POST['search_term'];
        $results = searchUsers($term);
        echo "Found " . count($results) . " users";
    }
    
    if (isset($_POST['create_user'])) {
        // VULNERABLE: Create user
        $username = $_POST['username'];
        $email = $_POST['email'];
        $password = $_POST['password'];
        $role = $_POST['role'] ?? 'user';
        
        $id = createUser($username, $email, $password, $role);
        if ($id) {
            echo "User created with ID: $id";
        } else {
            echo "Failed to create user";
        }
    }
}

// Handle GET requests
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    if (isset($_GET['id'])) {
        // VULNERABLE: Get user by ID
        $id = $_GET['id'];
        $user = getUserById($id);
        if ($user) {
            echo "User: " . htmlspecialchars($user['username']);
        } else {
            echo "User not found";
        }
    }
    
    if (isset($_GET['sort']) && isset($_GET['order'])) {
        // VULNERABLE: Sort users
        $sort = $_GET['sort'];
        $order = $_GET['order'];
        $users = getUsersSorted($sort, $order);
        echo "Sorted users: " . count($users);
    }
    
    if (isset($_GET['product_search'])) {
        // VULNERABLE: Product search
        $keyword = $_GET['keyword'];
        $products = searchProducts($keyword);
        echo "Found " . count($products) . " products";
    }
}

// Close connection
mysqli_close($conn);
?>
