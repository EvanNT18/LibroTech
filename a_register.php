<?php
require 'koneksi.php';

if ($_SERVER['REQUEST_METHOD'] == "POST") {
    $username = test_input($_POST["username"]);
    $email = test_input($_POST["email"]);
    $password = test_input($_POST["password"]); // Plain text password (insecure)

    // Check for duplicate username using prepared statements
    $stmt = $conn->prepare("SELECT * FROM user WHERE username = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $stmt->store_result();
    $num = $stmt->num_rows;
    $stmt->close();

    if ($num == 0) {
        // Insert new user using prepared statement
        $stmt = $conn->prepare("INSERT INTO user (username, email, password) VALUES (?, ?, ?)");
        $stmt->bind_param("sss", $username, $email, $password);

        if ($stmt->execute()) {
            echo "<script>alert('Registration successful!'); window.location.href = 'a_login.html';</script>";
        } else {
            echo "<script>alert('Error: Could not execute the query.'); window.location.href = 'a_register.html';</script>";
        }
        $stmt->close();
    } else {
        echo "<script>alert('Username is not available.'); window.location.href = 'a_register.html';</script>";
    }
}

function test_input($data)
{
    $data = trim($data);
    $data = stripslashes($data);
    $data = htmlspecialchars($data);
    return $data;
}
