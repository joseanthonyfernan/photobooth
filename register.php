<?php
// register.php
require 'secure_db.php';

$errors = [];
$success_message = "";

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // 3. Sanitize user input to remove unwanted characters/HTML tags to prevent XSS
    $raw_username = $_POST['username'] ?? '';
    // strip_tags removes HTML tags, htmlspecialchars converts special chars
    $username = htmlspecialchars(strip_tags(trim($raw_username)), ENT_QUOTES, 'UTF-8');

    // Passwords generally shouldn't be HTML-stripped to allow complex symbols, but we'll trim it
    $password = $_POST['password'] ?? '';

    // 1. Validate Username: alphanumeric, 5-20 characters
    if (!preg_match('/^[a-zA-Z0-9]{5,20}$$/', $username)) {
        $errors[] = "Username must be exactly 5 to 20 characters long and contain only alphanumeric characters.";
    }

    // Validate Password Complexity: min 8 chars, uppercase, lowercase, digit, special character
    if (strlen($password) < 8 || 
        !preg_match('/[A-Z]/', $password) || 
        !preg_match('/[a-z]/', $password) || 
        !preg_match('/[0-9]/', $password) || 
        !preg_match('/[\W_]/', $password)) {
        $errors[] = "Password must be at least 8 characters long and include at least one uppercase letter, one lowercase letter, one number, and one special character.";
    }

    // 5. If all input is valid, process the registration
    if (empty($errors)) {
        // Hash password securely (using SHA-256 to match the tutorial's login_vulnerable setup)
        $hashed_password = hash('sha256', $password);

        // Prepared statements inherently prevent SQL Injection
        $stmt = $conn->prepare("INSERT INTO users (username, password) VALUES (?, ?)");
        
        if ($stmt) {
            $stmt->bind_param("ss", $username, $hashed_password);
            try {
                if ($stmt->execute()) {
                    $success_message = "Registration successful! You can now log in.";
                    // Clear the form fields after successful registration
                    $username = "";
                } else {
                    $errors[] = "Error: Could not register user. That username might already be taken.";
                }
            } catch (mysqli_sql_exception $e) {
                if ($e->getCode() == 1062) { // 1062 is the MySQL error code for duplicate entry
                    $errors[] = "Error: That username is already taken. Please choose another.";
                } else {
                    $errors[] = "Database error: " . $e->getMessage();
                }
            }
            $stmt->close();
        } else {
            $errors[] = "Database preparation error: " . $conn->error;
        }
    }
}
?>
<!DOCTYPE html>
<html>

<head>
    <title>Register</title>
</head>

<body>
    <h2>User Registration</h2>
    
    <!-- 4. Display appropriate error messages and prevent form submission processing -->
    <?php 
    if (!empty($errors)) {
        echo "<div style='color:red;'><strong>Please fix the following errors:</strong><ul>";
        foreach ($errors as $error) {
            echo "<li>$error</li>";
        }
        echo "</ul></div>";
    }
    
    if ($success_message) {
        echo "<p style='color:green;'><strong>$success_message</strong></p>";
    }
    ?>

    <form method="POST" action="">
        <label>Username:</label><br>
        <input type="text" name="username" value="<?php echo htmlspecialchars($username ?? '', ENT_QUOTES); ?>" required><br>
        <small>5-20 characters, alphanumeric only.</small><br><br>
        

        <label>Password:</label><br>
        <input type="password" name="password" required><br>
        <small>Min 8 chars, 1 uppercase, 1 lowercase, 1 number, 1 special character.</small><br><br>
        
        <button type="submit">Register</button>
    </form>
    <p><a href="index.php">Back to Home</a></p>
</body>

</html>