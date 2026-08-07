<!DOCTYPE html>
<html>
<head>
    <title>User Authentication Project</title>
</head>
<body>
    <h1>User Authentication & SQL Injection Demonstration</h1>
    <p>This project fulfills the assignment requirements by demonstrating the difference between vulnerable and secure login implementations.</p>
    
    <ul>
        <li><a href="register.php">Register a New User</a></li>
        <li><a href="login_vulnerable.php">Login (VULNERABLE)</a></li>
        <li><a href="login_secure.php">Login (SECURE)</a></li>
    </ul>

    <h2>Setup Instructions:</h2>
    <p>Please import <code>database.sql</code> into your MySQL server (via phpMyAdmin or command line) before testing the application to create the necessary <code>user_auth_demo</code> database and <code>users</code> table.</p>
    
    <h2>Project Overview (Steps fulfilled):</h2>
    <ol>
        <li><strong>Database Schema</strong>: Defined in <code>database.sql</code> with id, username, and password.</li>
        <li><strong>Registration</strong>: Handled in <code>register.php</code> with secure password hashing (SHA-256 for demonstration compatibility).</li>
        <li><strong>Login Versions</strong>: <code>login_vulnerable.php</code> concatenates inputs. <code>login_secure.php</code> uses prepared statements.</li>
        <li><strong>Testing</strong>: Instructions provided on login pages to test valid/invalid credentials and injection.</li>
        <li><strong>Comparison</strong>: The vulnerable version executes injections (e.g., bypassing password checks with <code>--</code>), while the secure version treats all input literally, failing safely.</li>
        <li><strong>Explanations</strong>: Detailed comments and explanations are present in both PHP scripts to clarify how prepared statements prevent SQL injection.</li>
    </ol>
</body>
</html>
