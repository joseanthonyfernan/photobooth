<?php
// login_vulnerable.php
require 'vulnerable_db.php';

$message = "";

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';

    // Step 3a: Vulnerable version
    // EXPLANATION: Here we concatenate the user input directly into the SQL query string.
    // This allows an attacker to inject arbitrary SQL commands.
    // For example, if username is: ' OR '1'='1' -- 
    // The query becomes: SELECT * FROM users WHERE username = '' OR '1'='1' -- ' AND password = '...'
    // The '-- ' tells MySQL to comment out the rest of the line, ignoring the password check completely!

    // Using the raw $password input makes this completely vulnerable in both fields
    $sql = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";

    // Execute query directly without parameterization
    try {
        $result = $conn->query($sql);

        // If a row is returned, authentication is considered successful
        if ($result && $result->num_rows > 0) {
            $user = $result->fetch_assoc();
            $message = "Welcome, " . htmlspecialchars($user['username']) . "! (Logged in via VULNERABLE method)";
        } else {
            $message = "Invalid username or password.";
        }
    } catch (mysqli_sql_exception $e) {
        // Catch the fatal error and show it to the user so they can see the injection broke the query!
        $message = "SQL Syntax Error (Your injection worked, but the syntax was slightly off!):<br>" . htmlspecialchars($e->getMessage());
    }
}
?>
<!DOCTYPE html>
<html>

<head>
    <title>Vulnerable Login</title>
</head>

<body>
    <h2>Vulnerable Login (DO NOT USE IN PRODUCTION)</h2>
    <?php if ($message)
        echo "<p style='color:red;'><strong>$message</strong></p>"; ?>
    <form method="POST" action="">
        <label>Username:</label><br>
        <input type="text" name="username" required><br><br>
        <label>Password:</label><br>
        <!-- Removed 'required' on password so it's easier to test the injection -->
        <input type="text" name="password"><br><br>
        <button type="submit">Login</button>
    </form>

    <hr>
    <h3>Step 4 & 5: Try SQL Injection!</h3>
    <p>To demonstrate the risk, try logging in with:</p>
    <ul>
        <li>Username: <code>' OR '1'='1' -- </code> (Notice the space after the dashes)</li>
        <li>Username: <code>admin' #</code> (Alternative: Using # is easier as it doesn't require a trailing space)</li>
        <li>Password: <code>(leave blank or type anything)</code></li>
    </ul>
    <p>The <code>-- </code> or <code>#</code> comments out the password requirement, allowing you to log in as 'admin'
        without knowing the
        password. This is why concatenating input directly into SQL is dangerous.</p>
    <p><a href="index.php">Back to Home</a></p>
</body>

</html>