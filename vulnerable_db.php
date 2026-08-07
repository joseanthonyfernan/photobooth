<?php
// db.php - Database connection setup

$host = 'localhost';
$dbname = 'vulnerable_user_auth_demo';
$user = 'root';
$pass = ''; // Default XAMPP password is empty

// We use mysqli for demonstration to easily show both vulnerable and secure queries
$conn = new mysqli($host, $user, $pass, $dbname);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}
?>