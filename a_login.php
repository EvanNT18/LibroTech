<?php
require 'koneksi.php';
session_start();

if ($_SERVER['REQUEST_METHOD'] == "POST") {
    $username = test_input($_POST["username"]);
    $password = test_input($_POST["password"]);

    // Ensure that username/email and password are not empty
    if (empty($username) || empty($password)) {
        echo "<script>alert('Username/email and password are required');</script>";
    } else {
        // Use prepared statement to prevent SQL injection
        $stmt = $conn->prepare("SELECT * FROM user WHERE username = ? OR email = ?");
        $stmt->bind_param("ss", $username, $username);
        $stmt->execute();
        $result = $stmt->get_result();
        $row = $result->fetch_assoc();

        // Check username on existing table
        $q = mysqli_query($conn, "SELECT * FROM user WHERE username='" . $username . "'");
        if (mysqli_num_rows($q) > 0) {
            echo "<script>alert('login succes'); window.location.href = 'b_home.html';</script>";
        }

        // Check user password
        if ($result->num_rows > 0) {
            // Verify the password if it's hashed
            if (password_verify($password, $row["password"])) {
                // Regenerate session ID to prevent session fixation
                session_regenerate_id(true);

                // Start session and set session variables
                $_SESSION["login"] = true;
                $_SESSION["id"] = $row["id"];
                header("Location: b_home.html");
                exit();
            } else {
                // Incorrect Password
                echo "<script>alert('Incorrect password'); window.location.href = 'a_login.html';</script>";
            }

            $stmt->close();
        }
    }
}

function test_input($data)
{
    $data = trim($data);
    $data = stripslashes($data);
    $data = htmlspecialchars($data);
    return $data;
}
