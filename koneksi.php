<?php
// session_start();
// $conn = mysqli_connect("localhost", "root", "", "db_reglog_dl");

$servername = "localhost";
$username = "root";
$password = "";

$database = "db_libro";

$conn = mysqli_connect($servername, $username, $password, $database);

if ($conn) {
    echo "success";
} else {
    die("Error" . mysqli_connect_error());
}
