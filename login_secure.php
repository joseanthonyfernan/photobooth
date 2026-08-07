<?php
// login_secure.php
require 'secure_db.php';
$message = "";
$msg_color = "red"; // Default color is red for all errors

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // 1. Input Validation and Sanitation
    // Sanitize the username to prevent XSS if ever reflected, and trim whitespace
    $username_input = filter_input(INPUT_POST, 'username', FILTER_SANITIZE_FULL_SPECIAL_CHARS);
    $username = trim((string) $username_input);

    // Passwords should not be sanitized or trimmed to allow special characters
    $password = $_POST['password'] ?? '';

    // Validate that inputs are not empty
    if (empty($username) || empty($password)) {
        $message = "Error: Username and password are required.";
    } else {
        // Hash the password so it matches the DB representation
        $hashed_password = hash('sha256', $password);

        // 2 & 3. Parameterized queries and Proper error handling
        try {
            $stmt = $conn->prepare("SELECT id, username, password FROM users WHERE username = ? AND password = ?");

            // Check if preparation failed (for PHP versions where mysqli exceptions are not default)
            if (!$stmt) {
                throw new Exception("Database preparation error.");
            }

            // Bind parameters to the query ("ss" means two strings)
            $stmt->bind_param("ss", $username, $hashed_password);

            // Execute and verify success
            if (!$stmt->execute()) {
                throw new Exception("Database execution error.");
            }

            $result = $stmt->get_result();

            if ($result && $result->num_rows > 0) {
                $user = $result->fetch_assoc();
                $message = "Welcome, " . htmlspecialchars($user['username']) . "! (Logged in securely)";
                $msg_color = "green"; // Change to green on success
            } else {
                // Keep generic error for invalid credentials to avoid user enumeration
                $message = "Invalid username or password.";
            }

            $stmt->close();
        } catch (mysqli_sql_exception $e) {
            // Log the exact database error, but do not expose it to the user
            error_log("MySQL Error: " . $e->getMessage());
            $message = "An internal database error occurred. Please try again later.";
        } catch (Exception $e) {
            // Log general exceptions
            error_log("Application Error: " . $e->getMessage());
            $message = "An unexpected system error occurred.";
        }
    }
}
?>
<!DOCTYPE html>
<html>

<head>
    <title>Secure Login</title>
</head>

<body>
    <h2>Secure Login</h2>
    <?php if ($message)
        echo "<p style='color:$msg_color;'><strong>$message</strong></p>"; ?>
    <form method="POST" action="">
        <label>Username:</label><br>
        <input type="text" name="username" required><br><br>
        <label>Password:</label><br>
        <input type="password" name="password" required><br><br>
        <button type="submit">Login</button>
    </form>

    <hr>
    <h3>Step 4 & 5: Try SQL Injection!</h3>
    <p>Try the same injections here (e.g. <code>admin' -- </code>).</p>
    <p>They will fail because the prepared statement ensures the input is treated strictly as data, preventing the
        database from executing malicious commands.</p>
    <p><a href="index.php">Back to Home</a></p>
</body>

</html>