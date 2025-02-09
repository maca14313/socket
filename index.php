<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);

// CORS headers
header('Access-Control-Allow-Origin: http://localhost:5173
');
header('Access-Control-Allow-Credentials: true');
header('Access-Control-Allow-Methods: POST, GET, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

/*
ini_set('upload_max_filesize', '20M');
ini_set('post_max_size', '25M');
ini_set('memory_limit', '256M');
ini_set('max_execution_time', '300');

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    error_log("POST: " . print_r($_POST, true));
    error_log("FILES: " . print_r($_FILES, true));

    if (move_uploaded_file($_FILES['audio_file']['tmp_name'], __DIR__ . '/uploads/' . $_FILES['audio_file']['name'])) {
        echo json_encode(["message" => "File uploaded successfully"]);
    } else {
        echo json_encode(["message" => "Failed to upload file"]);
    }
}
*/

ini_set('upload_max_filesize', '50M'); // Adjust this to your needed maximum file size (e.g., 50 MB)
ini_set('post_max_size', '55M');       // Needs to be slightly larger than upload_max_filesize
ini_set('memory_limit', '256M');       // Memory limit for PHP processing
ini_set('max_execution_time', '300');  // Increase execution time if needed for large files


// Include dependencies
require 'vendor/autoload.php'; // For JWT, Dotenv
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Behat\Transliterator\Transliterator;

// Load environment variables
$dotenv = Dotenv\Dotenv::createImmutable(__DIR__);
$dotenv->load();

// Database connection
/*
$host = 'localhost:3306';
$user = 'root';
$password = '0925090339';
$dbname = 'DrDb';
$dsn = "mysql:host=$host;dbname=$dbname";
$pdo = new PDO($dsn, $user, $password, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]); */

$host = $_ENV['DB_HOST'];
$user = $_ENV['DB_USERNAME'];
$password = $_ENV['DB_PASSWORD'];
$dbname = $_ENV['DB_DATABASE'];
$dsn = "mysql:host=$host;dbname=$dbname";
$pdo = new PDO($dsn, $user, $password, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);

/////////////////////////////////////////////////////////////////////////////////////////////

// Create tables if they do not exist
function createTables($pdo) {
    $queries = [


       "CREATE TABLE IF NOT EXISTS login (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(255) NOT NULL UNIQUE,
            password VARCHAR(255) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
          )",
        // books table
        "CREATE TABLE IF NOT EXISTS books (
            id INT AUTO_INCREMENT PRIMARY KEY,
            title VARCHAR(255) NOT NULL,
            pdf_name VARCHAR(255) NOT NULL,
            bookCategory VARCHAR(255) NOT NULL,
            description TEXT,
            img_name VARCHAR(255),
            author VARCHAR(255) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        )",

        // videos table
        "CREATE TABLE IF NOT EXISTS videos (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            videoCategory VARCHAR(255) NOT NULL,
            videoLink TEXT NOT NULL,
            createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )",
       
        // AudioBooks table
        "CREATE TABLE IF NOT EXISTS audioBooks (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )",

        // Units table
        "CREATE TABLE IF NOT EXISTS units (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            book_id INT NOT NULL,
            createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (book_id) REFERENCES audioBooks(id) ON DELETE CASCADE
        )",

        // Topics table
        "CREATE TABLE IF NOT EXISTS topics (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            unit_id INT NOT NULL,
            createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (unit_id) REFERENCES units(id) ON DELETE CASCADE
        )",

        // Audio files table
        "CREATE TABLE IF NOT EXISTS audio_files (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            audioText TEXT NOT NULL,
            file_path VARCHAR(255) NOT NULL,
            topic_id INT NOT NULL,
            createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (topic_id) REFERENCES topics(id) ON DELETE CASCADE
        )",

        // Audio files with type table
        "CREATE TABLE IF NOT EXISTS audio_types (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            category VARCHAR(255) NOT NULL,
            file_path VARCHAR(255) NOT NULL,
            createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )",

        // ask fetwa table
        "CREATE TABLE IF NOT EXISTS askFetwa (
            id INT AUTO_INCREMENT PRIMARY KEY,
            postText TEXT NOT NULL,
            posterId VARCHAR(255) NOT NULL,
            pending VARCHAR(255) NOT NULL,
            createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )",
        
        // answer fetwa table
        "CREATE TABLE IF NOT EXISTS answerFetwa (
            id INT AUTO_INCREMENT PRIMARY KEY,
            answerTitle TEXT NOT NULL,
            postText TEXT NOT NULL,
            posterId VARCHAR(255) NOT NULL,
            createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            askFetwa_id VARCHAR(255) NOT NULL
        )"
    ];
//FOREIGN KEY (askFetwa_id) REFERENCES askFetwa(id) ON DELETE CASCADE
    foreach ($queries as $query) {
        try {
            $pdo->exec($query);
        } catch (PDOException $e) {
            error_log("Table creation error: " . $e->getMessage());
            echo json_encode(['message' => 'Error creating tables', 'success' => false]);
            exit();
        }
    }
}
createTables($pdo);
///////////////////////////////////////////////////////////////////////////////////////////

// Request method and URI
$requestMethod = $_SERVER['REQUEST_METHOD'];
$requestUri = $_SERVER['REQUEST_URI'];

// Log request method and URI for debugging

error_log("Request Method: " . $requestMethod);
error_log("Request URI: " . $requestUri);

// Normalize URI by removing query parameters and trailing slash
$requestUri = strtok($requestUri, '?');
$requestUri = rtrim($requestUri, '/');

// Log the normalized request URI
error_log("Normalized Request URI: " . $requestUri);

// Middleware to verify JWT token
function verifyToken($pdo) {
    $token = $_COOKIE['access_token'] ?? null;

    if (!$token) {
        echo json_encode(['message' => 'No token provided', 'success' => false, 'error' => 'Unauthorized', 'result' => null]);
        exit();
    }

    try {
        $decoded = JWT::decode($token, new Key($_ENV['JWT_SECRET'], 'HS256'));
        return $decoded;
    } catch (Exception $e) {
        echo json_encode(['message' => 'Invalid or expired token', 'success' => false, 'error' => 'Unauthorized', 'result' => null]);
        exit();
    }
}


///////////////////////////////////////////////////////////////////////////////////////////////////////////
// Register Route (Only One Admin Allowed)
if ($requestMethod === 'POST' && preg_match('#^/register$#', $requestUri)) {
    // Parse JSON input
    $input = json_decode(file_get_contents('php://input'), true);
    $username = $input['username'] ?? null;
    $password = $input['password'] ?? null;

    // Check if username and password are set
    if (!$username || !$password) {
        echo json_encode([
            'error' => 'Missing username or password',
            'message' => 'Please provide both username and password',
            'success' => false,
            'result' => null
        ]);
        exit();
    }

    try {
        // Check if admin already exists
        $stmt = $pdo->prepare('SELECT * FROM login');
        $stmt->execute();
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

        if (count($rows) > 0) {
            echo json_encode([
                'error' => 'Admin already exists',
                'message' => 'Admin already exists',
                'success' => false,
                'result' => null
            ]);
            exit();
        }

        // Hash password and insert new admin
        $hashedPassword = password_hash($password, PASSWORD_BCRYPT);
        $stmt = $pdo->prepare('INSERT INTO login (username, password) VALUES (?, ?)');
        $stmt->execute([$username, $hashedPassword]);

        echo json_encode([
            'message' => 'Admin registered successfully',
            'success' => true,
            'error' => null,
            'result' => null
        ]);
        exit();

    } catch (PDOException $e) {
        error_log("Error: " . $e->getMessage());
        echo json_encode([
            'error' => 'Internal server error',
            'message' => 'Internal server error',
            'success' => false,
            'result' => null
        ]);
        exit();
    }
}

// Login route
if ($requestUri === '/login' && $requestMethod === 'POST') {
    $input = json_decode(file_get_contents('php://input'), true);
    $username = $input['username'];
    $password = $input['password'];

    $stmt = $pdo->prepare('SELECT * FROM login WHERE username = ?');
    $stmt->execute([$username]);
    $user = $stmt->fetch();

    if (!$user || !password_verify($password, $user['password'])) {
        echo json_encode(['message' => 'Invalid username or password', 'success' => false, 'result' => null]);
        exit();
    }

    $token = JWT::encode(['id' => $user['id'], 'username' => $user['username']], $_ENV['JWT_SECRET'], 'HS256');

    setcookie('access_token', $token, time() + (60 * 60), '/', '', false, true);

    echo json_encode(['message' => 'Login successful', 'success' => true, 'result' => null]);
    exit();
}

// Logout route
if ($requestUri === '/logout' && $requestMethod === 'POST') {
    setcookie('access_token', '', time() - 3600, '/');
    echo json_encode(['message' => 'Logged out']);
    
} 

///////////////////////////////////////////////////////////////////////////////////////////////////////////

// Add book route (Protected)
if ($requestUri === '/books' && $requestMethod === 'POST') {
    verifyToken($pdo); // Ensure user is authenticated

    // Log incoming POST data and files for debugging
    error_log("POST /books endpoint hit.");
    error_log("Request URI: $requestUri");
    error_log(json_encode($_POST));
    error_log(json_encode($_FILES));

    $title = $_POST['title'];
    $description = $_POST['description'];
    $author = $_POST['author'];
    $bookCategory = $_POST['bookCategory'];
    $img = $_FILES['img']['name'] ?? null;
    $pdf = $_FILES['pdf']['name'] ?? null;
    

    // Validate image size (if provided)
    if ($img && $_FILES['img']['size'] > 1000 * 1024) {
        echo json_encode(['message' => 'Image size exceeds 200 KB limit. Upload cancelled.', 'success' => false]);
        exit();
    }

    // Check if a PDF file is provided
    if (!$pdf) {
        echo json_encode(['message' => 'PDF file is required', 'success' => false]);
        exit();
    }

    // Directory for storing uploaded files
    $uploadDir = __DIR__ . '/uploads/';
    if (!is_dir($uploadDir)) {
        mkdir($uploadDir, 0755, true); // Create directory if it doesn't exist
    }

    // Extract file extensions
    $pdfExtension = pathinfo($_FILES['pdf']['name'], PATHINFO_EXTENSION);
    $imgExtension = $img ? pathinfo($_FILES['img']['name'], PATHINFO_EXTENSION) : null;

    // Use the title as the filename and append the correct extensions
    $sanitizedTitle = preg_replace('/[^a-zA-Z0-9_-]/', '_', $title); // Replace invalid characters with '_'
    $pdfFilename = $sanitizedTitle . '.' . $pdfExtension;
    $imgFilename = $img ? $sanitizedTitle . '.' . $imgExtension : null;

    // Full file paths
    $pdfPath = $uploadDir . $pdfFilename;
    $imgPath = $img ? $uploadDir . $imgFilename : null;

    // Move the uploaded files to the uploads directory
    if (!move_uploaded_file($_FILES['pdf']['tmp_name'], $pdfPath)) {
        echo json_encode(['message' => 'Failed to upload PDF file', 'success' => false]);
        exit();
    }

    if ($img && !move_uploaded_file($_FILES['img']['tmp_name'], $imgPath)) {
        echo json_encode(['message' => 'Failed to upload image file', 'success' => false]);
        exit();
    }

    // Check for duplicate PDFs in the database
    $stmt = $pdo->prepare('SELECT * FROM books WHERE pdf_name = ?');
    $stmt->execute([$pdfFilename]);
    $existingPdf = $stmt->fetch();

    if ($existingPdf) {
        echo json_encode(['message' => 'This PDF file already exists', 'success' => false]);
        exit();
    }

    // Insert new book record into the database
    $stmt = $pdo->prepare('INSERT INTO books (title, pdf_name, description, bookCategory,img_name, author) VALUES (?, ?, ?, ?, ?,?)');
    $stmt->execute([$title, $pdfFilename, $description,$bookCategory, $imgFilename, $author]);
    error_log('okkkkkkkkkk');
    echo json_encode(['message' => 'Book added successfully', 'success' => true]);
    exit();
}

// Get books route
if ($requestUri === '/books' && $requestMethod === 'GET') {
    error_log("GET /books endpoint hit.");

    // Get pagination parameters
    $page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
    $limit = isset($_GET['limit']) ? (int)$_GET['limit'] : 10;
    $offset = ($page - 1) * $limit;

    try {
        // Fetch total number of books
        $stmt = $pdo->prepare('SELECT COUNT(*) AS total FROM books');
        $stmt->execute();
        $totalBooks = $stmt->fetch()['total'];
        
        // Log total number of books to the terminal
        error_log("Total number of books: " . $totalBooks);

        // Fetch books with pagination
        $stmt = $pdo->prepare('SELECT * FROM books LIMIT ? OFFSET ?');
        $stmt->bindValue(1, (int)$limit, PDO::PARAM_INT);
        $stmt->bindValue(2, (int)$offset, PDO::PARAM_INT);
        $stmt->execute();
        $books = $stmt->fetchAll(PDO::FETCH_ASSOC);

        // Prepare the JSON response
        $response = [
            'message' => 'Books retrieved successfully',
            'success' => true,
            'error' => null,
            'result' => [
                'total' => $totalBooks,
                'books' => $books,
                'currentPage' => $page,
                'totalPages' => ceil($totalBooks / $limit)
            ]
        ];

        // Log the response to the terminal
       // error_log(json_encode($response));
        
        // Respond with JSON
        echo json_encode($response);
        exit();

    } catch (PDOException $e) {
        // Prepare error response
        $errorResponse = json_encode([
            'message' => 'Internal server error',
            'success' => false,
            'error' => $e->getMessage(),
            'result' => null
        ]);

        // Log the error response to the terminal
        error_log($errorResponse);

        // Respond with the error JSON
        echo $errorResponse;
        exit();
    }
}

// Get  Books Categorys
if ($requestUri === '/getbookscategorys' && $requestMethod === 'GET') {

    // Log request details
    error_log("GET /getaudioscategorys endpoint hit.");

    try {
        // Fetch distinct, non-null categories
        $stmt = $pdo->prepare('SELECT DISTINCT LOWER(bookCategory) AS category FROM books WHERE bookCategory IS NOT NULL');
        $stmt->execute();
        $categories = $stmt->fetchAll(PDO::FETCH_COLUMN); // Fetch as a flat array of category strings

        if (!empty($categories)) {
            echo json_encode(['message' => 'Categories fetched', 'success' => true, 'result' => $categories]);
        } else {
            echo json_encode(['message' => 'No categories found', 'success' => false, 'result' => []]);
        }
    } catch (PDOException $e) {
        // Log the error and respond with an error message
        error_log("Database error: " . $e->getMessage());
        echo json_encode([
            'message' => 'Internal server error',
            'success' => false,
            'error' => $e->getMessage(),
            'result' => null
        ]);
    }

    exit();
}

// Get  Books by Categorys
if ($requestUri === '/getbooksbycategory' && $requestMethod === 'GET') {
    //verifyToken($pdo);
    error_log("GET /books by category endpoint hit.");

    // Get pagination parameters
    $page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
    $limit = isset($_GET['limit']) ? (int)$_GET['limit'] : 5; // Changed from 10 to 5 if needed
    $offset = ($page - 1) * $limit;
    $category = $_GET['category'] ?? null;

    try {
        // Fetch total number of `books` entries with category
        $stmt = $pdo->prepare('SELECT COUNT(*) AS total FROM books WHERE bookCategory = :category');
        $stmt->execute([':category' => $category]);
        $totalBooksByCategory = $stmt->fetch()['total'];
        
        // Log total number of books to the terminal
        error_log("Total number of books by category: " . $totalBooksByCategory);

        // Fetch `books` entries with pagination
        $stmt = $pdo->prepare('SELECT * FROM books WHERE bookCategory = :category ORDER BY created_at DESC LIMIT :limit OFFSET :offset');
        $stmt->bindValue(':category', $category, PDO::PARAM_STR);
        $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
        $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
        $stmt->execute();
        $books = $stmt->fetchAll(PDO::FETCH_ASSOC);

        // Prepare the JSON response
        $response = [
            'message' => 'Books retrieved successfully',
            'success' => true,
            'error' => null,
            'result' => [
                'total' => $totalBooksByCategory,
                'books' => $books,
                'currentPage' => $page,
                'totalPages' => ceil($totalBooksByCategory / $limit),
                'limit' => $limit
            ]
        ];

        // Respond with JSON
        echo json_encode($response);
        exit();

    } catch (PDOException $e) {
        // Prepare error response
        $errorResponse = [
            'message' => 'Internal server error',
            'success' => false,
            'error' => $e->getMessage(),
            'result' => null
        ];

        // Log the error response to the terminal
        error_log(json_encode($errorResponse));

        // Respond with the error JSON
        echo json_encode($errorResponse);
        exit();
    }
}

// Update book route (Protected) 
if ($requestMethod === 'POST' && preg_match('#^/update/books/(\d+)$#', $requestUri, $matches)) {    verifyToken($pdo); // Ensure user is authenticated
    error_log('bbbbbbbbbbbbbbbbbbbb');

    $id = $matches[1];
    $title = $_POST['title'];
    $description = $_POST['description'];
    $author = $_POST['author'];
    $bookCategory = $_POST['bookCategory'];
    $img = $_FILES['img']['name'] ?? null;
    $pdf = $_FILES['pdf']['name'] ?? null;

    // Log the incoming data for debugging
    error_log('Updating book ID: ' . $id);
    error_log(json_encode($_POST));
    error_log(json_encode($_FILES));

    try {
        // Fetch the existing book details
        $stmt = $pdo->prepare('SELECT * FROM books WHERE id = ?');
        $stmt->execute([$id]);
        $existingBook = $stmt->fetch(PDO::FETCH_ASSOC);
        
       

        if (!$existingBook) {
            echo json_encode(['message' => 'Book not found', 'success' => false, 'error' => 'Not Found']);
            exit();
        }

        // Validate image size if a new image is uploaded
        if ($img && $_FILES['img']['size'] > 500 * 1024) {
            echo json_encode(['message' => 'Image size exceeds 200 KB limit.', 'success' => false]);
            exit();
        }

        // Check for duplicate PDFs if a new PDF is uploaded
        if ($pdf) {
            $stmt = $pdo->prepare('SELECT * FROM books WHERE pdf_name = ? AND id != ?');
            $stmt->execute([$pdf, $id]);
            $duplicatePdf = $stmt->fetch();

            if ($duplicatePdf) {
                echo json_encode(['message' => 'This PDF file already exists.', 'success' => false]);
                exit();
            }
        }

        // Define the upload directory
        $uploadDir = __DIR__ . '/uploads/';

        // Handle old file deletion and set new filenames
        if ($img && $existingBook['img_name']) {
            @unlink($uploadDir . $existingBook['img_name']);
        }
        if ($pdf && $existingBook['pdf_name']) {
            @unlink($uploadDir . $existingBook['pdf_name']);
        }

        // Sanitize the title for filenames
        $sanitizedTitle = preg_replace('/[^a-zA-Z0-9_-]/', '_', $title);
        $pdfFilename = $pdf ? $sanitizedTitle . '.' . pathinfo($_FILES['pdf']['name'], PATHINFO_EXTENSION) : $existingBook['pdf_name'];
        $imgFilename = $img ? $sanitizedTitle . '.' . pathinfo($_FILES['img']['name'], PATHINFO_EXTENSION) : $existingBook['img_name'];

        // Move uploaded files to the uploads directory
        if ($pdf && !move_uploaded_file($_FILES['pdf']['tmp_name'], $uploadDir . $pdfFilename)) {
            echo json_encode(['message' => 'Failed to upload PDF file', 'success' => false]);
            exit();
        }
        if ($img && !move_uploaded_file($_FILES['img']['tmp_name'], $uploadDir . $imgFilename)) {
            echo json_encode(['message' => 'Failed to upload image file', 'success' => false]);
            exit();
        }

        // Update the book record in the database
        $stmt = $pdo->prepare('UPDATE books SET title = ?, description = ?,bookCategory = ?, author = ?, img_name = ?, pdf_name = ? WHERE id = ?');
        $stmt->execute([$title, $description, $bookCategory,$author, $imgFilename, $pdfFilename, $id]);

        echo json_encode(['message' => 'Book updated successfully', 'success' => true]);
        exit();
    } catch (PDOException $e) {
        error_log("Error updating book: " . $e->getMessage());
        echo json_encode(['message' => 'Internal server error', 'success' => false, 'error' => 'Internal Server Error']);
        exit();
    }
}

// Get Single Book by ID
if ($requestMethod === 'GET' && preg_match('#^/books/(\d+)$#', $requestUri, $matches)) {
    $bookId = $matches[1]; // Extract the book ID from the URL

    try {
        // Fetch book by ID
        $stmt = $pdo->prepare('SELECT * FROM books WHERE id = ?');
        $stmt->execute([$bookId]);
        $book = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$book) {
            // If the book is not found, return a 404 response
            echo json_encode([
                'message' => 'Book not found',
                'success' => false,
                'error' => 'Not Found',
                'result' => null
            ]);
            http_response_code(404);
            exit();
        }

        // If the book is found, return the book details
        echo json_encode([
            'message' => 'Book retrieved successfully',
            'success' => true,
            'error' => null,
            'result' => $book
        ]);
        exit();

    } catch (PDOException $e) {
        // Log error and return a 500 Internal Server Error response
        error_log("Error fetching book: " . $e->getMessage());
        echo json_encode([
            'message' => 'Internal server error',
            'success' => false,
            'error' => 'Internal server error',
            'result' => null
        ]);
        http_response_code(500);
        exit();
    }
} 

// Delete Book by ID (Protected)
if ($_SERVER['REQUEST_METHOD'] === 'DELETE' && preg_match('/^\/books\/(\d+)$/', $_SERVER['REQUEST_URI'], $matches)) {
    $id = $matches[1]; // Extract the book ID from the URI
    verifyToken($pdo); // Ensure user is authenticated

    try {
        $stmt = $pdo->prepare('SELECT * FROM books WHERE id = ?');
        $stmt->execute([$id]);
        $book = $stmt->fetch();

        if (!$book) {
            echo json_encode(['message' => 'Book not found', 'success' => false, 'error' => 'Not Found']);
            exit();
        }

        // Delete associated files
        $imgPath = "uploads/{$book['img_name']}";
        $pdfPath = "uploads/{$book['pdf_name']}";

        if (file_exists($imgPath)) unlink($imgPath);
        if (file_exists($pdfPath)) unlink($pdfPath);

        $stmt = $pdo->prepare('DELETE FROM books WHERE id = ?');
        $stmt->execute([$id]);

        echo json_encode(['message' => 'Book deleted successfully', 'success' => true]);
        exit();
    } catch (Exception $e) {
        error_log($e->getMessage());
        echo json_encode(['message' => 'Internal server error', 'success' => false, 'error' => 'Internal Server Error']);
    }
    exit();
}

//////////////////////////////////////////////////     AUDIOS      /////////////////////////////////////////////////////////////////////////


if ($requestUri === '/addaudiobooks' && $requestMethod === 'POST') {
    verifyToken($pdo);
    $input = json_decode(file_get_contents('php://input'), true);
    //$name = $input['name'] ?? null;
    $name = $_POST['name'];
    error_log($name);

    if (!$name) {
        echo json_encode(['message' => 'Book name is required', 'success' => false]);
        exit();
    }

    $stmt = $pdo->prepare('INSERT INTO audioBooks (name) VALUES (?)');
    $stmt->execute([$name]);
    echo json_encode(['message' => 'Book Name added successfully', 'success' => true]);
    error_log('looooooooooooooo');
    exit();
}


if ($requestUri === '/addunit' && $requestMethod === 'POST') {
    verifyToken($pdo);
    /*$input = json_decode(file_get_contents('php://input'), true);
    $name = $input['name'] ?? null;
    $bookId = $input['bookId'] ?? null; */

    $name = $_POST['name'];
    $bookId = $_POST['bookId'];

    if (!$name || !$bookId) {
        echo json_encode(['message' => 'Unit name and bookId are required', 'success' => false]);
        exit();
    }

    $stmt = $pdo->prepare('INSERT INTO units (name, book_id) VALUES (?, ?)');
    $stmt->execute([$name, $bookId]);
    echo json_encode(['message' => 'Unit added successfully', 'success' => true]);
    exit();
}

if ($requestUri === '/addtopics' && $requestMethod === 'POST') {
    verifyToken($pdo);
   /* $input = json_decode(file_get_contents('php://input'), true);
    $name = $input['name'] ?? null;
    $unitId = $input['unitId'] ?? null; */

    $name = $_POST['name'];
    $unitId = $_POST['unitId'];

    if (!$name || !$unitId) {
        echo json_encode(['message' => 'Topic name and unitId are required', 'success' => false]);
        exit();
    }

    $stmt = $pdo->prepare('INSERT INTO topics (name, unit_id) VALUES (?, ?)');
    $stmt->execute([$name, $unitId]);
    echo json_encode(['message' => 'Topic added successfully', 'success' => true]);
    exit();
}

if ($requestUri === '/addaudios' && $requestMethod === 'POST') {
    verifyToken($pdo); // Ensure user is authenticated

    // Log request details
    error_log("POST /audio endpoint hit.");
    error_log(print_r($_POST, true)); // Log POST data
    error_log(print_r($_FILES, true)); // Log FILES data

    // Get data from POST request
    $audioText = $_POST['audioText'] ?? null;
    $audioName = $_POST['name'] ?? null;
    $topicId = $_POST['topicId'] ?? null;
    $audioFile = $_FILES['audio_file'] ?? null;


    
 
  if (!$audioName || !$topicId || !$audioFile) {
        echo json_encode(['message' => 'Missing required fields', 'success' => false]);
        exit();
    }; 
 
   

    // Sanitize the audio name
    $sanitizedAudioName = preg_replace('/[^a-zA-Z0-9_-]/', '_', $audioName);
    $sanitizedAudioText = preg_replace('/[^a-zA-Z0-9_-]/', '_', $audioText);

    // Extract file extension
    $audioExtension = pathinfo($audioFile['name'], PATHINFO_EXTENSION);

    // Ensure the name is unique by appending a timestamp
    $finalAudioName = $sanitizedAudioName . '.' . $audioExtension;

    // Directory for storing uploaded audio files
    $uploadDir = __DIR__ . '/uploads/audio/';
    if (!is_dir($uploadDir)) {
        mkdir($uploadDir, 0755, true); // Create directory if it doesn't exist
    }

    // Full path for saving the file
    $filePath = $uploadDir . $finalAudioName;

    // Move the uploaded file to the target directory
    if (!move_uploaded_file($audioFile['tmp_name'], $filePath)) {
        echo json_encode(['message' => 'Failed to upload audio file', 'success' => false]);
        exit();
    }

    try {
        // Insert the audio file information into the database
        $stmt = $pdo->prepare('INSERT INTO audio_files (name, file_path, topic_id, audioText) VALUES (?, ?, ?,?)');
        $stmt->execute([$audioName, $finalAudioName, $topicId,$audioText]);

        echo json_encode(['message' => 'Audio file added successfully', 'success' => true]);
        exit();
    } catch (PDOException $e) {
        error_log("Database error: " . $e->getMessage());
        echo json_encode(['message' => 'Internal server error', 'success' => false]);
        exit();
    }
}

//add audios with type
if ($requestUri === '/addaudioswithtype' && $requestMethod === 'POST') {
    verifyToken($pdo); // Ensure user is authenticated

    // Log request details
    error_log("POST /audio endpoint hit.");
    error_log(print_r($_POST, true)); // Log POST data
    error_log(print_r($_FILES, true)); // Log FILES data

    // Get data from POST request category
    $audioName = $_POST['name'] ?? null;
    $audioFile = $_FILES['audio_file'] ?? null;
    $category = $_POST['category'] ?? null;

 
  if (!$audioName || !$audioFile || !$category) {
        echo json_encode(['message' => 'Missing required fields', 'success' => false]);
        exit();
    }; 

    // Sanitize the audio name
    $sanitizedAudioName = preg_replace('/[^a-zA-Z0-9_-]/', '_', $audioName);

    // Extract file extension
    $audioExtension = pathinfo($audioFile['name'], PATHINFO_EXTENSION);

    // Ensure the name is unique by appending a timestamp
    $finalAudioName = $sanitizedAudioName . '.' . $audioExtension;

    // Directory for storing uploaded audio files
    $uploadDir = __DIR__ . '/uploads/audio/';
    if (!is_dir($uploadDir)) {
        mkdir($uploadDir, 0755, true); // Create directory if it doesn't exist
    }

    // Full path for saving the file
    $filePath = $uploadDir . $finalAudioName;

    // Move the uploaded file to the target directory
    if (!move_uploaded_file($audioFile['tmp_name'], $filePath)) {
        echo json_encode(['message' => 'Failed to upload audio file', 'success' => false]);
        exit();
    }

    try {
        // Insert the audio file information into the database
        $stmt = $pdo->prepare('INSERT INTO audio_types (name, file_path,category) VALUES (?, ?,?)');
        $stmt->execute([$audioName, $finalAudioName, $category]);

        echo json_encode(['message' => 'Audio file added successfully', 'success' => true]);
        exit();
    } catch (PDOException $e) {
        error_log("Database error: " . $e->getMessage());
        echo json_encode(['message' => 'Internal server error', 'success' => false]);
        exit();
    }
}

// Get  Audio Categorys
if ($requestUri === '/getaudioscategorys' && $requestMethod === 'GET') {

    // Log request details
    error_log("GET /getaudioscategorys endpoint hit.");

    try {
        // Fetch distinct, non-null categories
        $stmt = $pdo->prepare('SELECT DISTINCT LOWER(category) AS category FROM audio_types WHERE category IS NOT NULL');
        $stmt->execute();
        $categories = $stmt->fetchAll(PDO::FETCH_COLUMN); // Fetch as a flat array of category strings

        if (!empty($categories)) {
            echo json_encode(['message' => 'Categories fetched', 'success' => true, 'result' => $categories]);
        } else {
            echo json_encode(['message' => 'No categories found', 'success' => false, 'result' => []]);
        }
    } catch (PDOException $e) {
        // Log the error and respond with an error message
        error_log("Database error: " . $e->getMessage());
        echo json_encode([
            'message' => 'Internal server error',
            'success' => false,
            'error' => $e->getMessage(),
            'result' => null
        ]);
    }

    exit();
}


///////////////////////////////////////////////////////////////////////////////////////////////////////////

// Get  Audio books route
if ($requestUri === '/audiobooks' && $requestMethod === 'GET') {
    error_log("GET / audio books endpoint hit.");

    try {
       
        // Query to retrieve the hierarchical data
        $stmt = $pdo->query("
            SELECT 
                b.id AS book_id, b.name AS book_name, b.createdAt AS book_created_at,
                u.id AS unit_id, u.name AS unit_name, u.createdAt AS unit_created_at,
                t.id AS topic_id, t.name AS topic_name, t.createdAt AS topic_created_at,
                a.id AS audio_id, a.name AS audio_name, a.file_path AS audio_file_path, a.audioText AS audioText ,a.createdAt AS audio_created_at
            FROM audioBooks b
            LEFT JOIN units u ON u.book_id = b.id
            LEFT JOIN topics t ON t.unit_id = u.id
            LEFT JOIN audio_files a ON a.topic_id = t.id
            ORDER BY b.id, u.id, t.id, a.id;
        ");
    
        // Organize data into a hierarchical structure
        $books = [];
        while ($row = $stmt->fetch()) {
            $bookId = $row['book_id'];
            $unitId = $row['unit_id'];
            $topicId = $row['topic_id'];
            $audioId = $row['audio_id'];
    
            if (!isset($books[$bookId])) {
                $books[$bookId] = [
                    "id" => $bookId,
                    "name" => $row['book_name'],
                    "createdAt" => $row['book_created_at'],
                    "units" => []
                ];
            }
    
            if ($unitId && !isset($books[$bookId]['units'][$unitId])) {
                $books[$bookId]['units'][$unitId] = [
                    "id" => $unitId,
                    "name" => $row['unit_name'],
                    "createdAt" => $row['unit_created_at'],
                    "topics" => []
                ];
            }
    
            if ($topicId && !isset($books[$bookId]['units'][$unitId]['topics'][$topicId])) {
                $books[$bookId]['units'][$unitId]['topics'][$topicId] = [
                    "id" => $topicId,
                    "name" => $row['topic_name'],
                    "createdAt" => $row['topic_created_at'],
                    "audios" => []
                ];
            }
    
            if ($audioId) {
                $books[$bookId]['units'][$unitId]['topics'][$topicId]['audios'][] = [
                    "id" => $audioId,
                    "name" => $row['audio_name'],
                    "audioText" => $row['audioText'],
                    "file_path" => $row['audio_file_path'],
                    "createdAt" => $row['audio_created_at']
                ];
            }
        }
    
        // Convert associative arrays to indexed arrays for JSON response
        $result = array_values(array_map(function ($book) {
            $book['units'] = array_values(array_map(function ($unit) {
                $unit['topics'] = array_values(array_map(function ($topic) {
                    $topic['audios'] = array_values($topic['audios']);
                    return $topic;
                }, $unit['topics']));
                return $unit;
            }, $book['units']));
            return $book;
        }, $books));
    
        // Send the JSON response
        echo json_encode([
            "message" => "Books retrieved successfully",
            "success" => true,
            "result" => $result,
            "error" => null
        ]);

        exit();

    } catch (PDOException $e) {
        // Handle errors
        echo json_encode([
            "message" => "Failed to retrieve books",
            "success" => false,
            "result" => null,
            "error" => $e->getMessage()
        ]);
        exit();
    }
}

// Get  Audio with type route by pagination
if ($requestUri === '/getaudiobytype' && $requestMethod === 'GET') {
    //verifyToken($pdo);
    error_log("GET /audio by types endpoint hit.");

    // Get pagination parameters
    $page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
    $limit = isset($_GET['limit']) ? (int)$_GET['limit'] : 5; // Changed from 10 to 5 to match JavaScript
    $offset = ($page - 1) * $limit;
    $category = $_GET['category'] ?? null;

    try {
        // Fetch total number of `audio_types` entries with category
        $stmt = $pdo->prepare('SELECT COUNT(*) AS total FROM audio_types WHERE category = :category');
        $stmt->execute([':category' => $category]);
        $totalAudioByType = $stmt->fetch()['total'];
        
        // Log total number of audio to the terminal
        error_log("Total number of audio by types: " . $totalAudioByType);

        // Fetch `audio_types` entries with pagination
        $stmt = $pdo->prepare('SELECT * FROM audio_types WHERE category = :category ORDER BY createdAt DESC LIMIT :limit OFFSET :offset');
        $stmt->bindValue(':category', $category, PDO::PARAM_STR);
        $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
        $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
        $stmt->execute();
        $audio = $stmt->fetchAll(PDO::FETCH_ASSOC);

        // Prepare the JSON response
        $response = [
            'message' => 'Audio retrieved successfully',
            'success' => true,
            'error' => null,
            'result' => [
                'total' => $totalAudioByType,
                'audio' => $audio,
                'currentPage' => $page,
                'totalPages' => ceil($totalAudioByType / $limit),
                'limit' => $limit
            ]
        ];

        // Respond with JSON
        echo json_encode($response);
        exit();

    } catch (PDOException $e) {
        // Prepare error response
        $errorResponse = [
            'message' => 'Internal server error',
            'success' => false,
            'error' => $e->getMessage(),
            'result' => null
        ];

        // Log the error response to the terminal
        error_log(json_encode($errorResponse));

        // Respond with the error JSON
        echo json_encode($errorResponse);
        exit();
    }
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////

// Update audio book route (Protected) 
if ($requestUri === '/updateaudiobook' && $requestMethod === 'POST') {   
     verifyToken($pdo); // Ensure user is authenticated
    error_log('bbbbbbbbbbbbbbbbbbbb');

    $id = $_POST['id'];
    $name=$_POST['name'];
    // Log the incoming data for debugging
    error_log('Updating book ID: ' . $id);
    error_log(json_encode($_POST));

    try {
        // Fetch the existing book details
        $stmt = $pdo->prepare('SELECT * FROM audioBooks WHERE id = ?');
        $stmt->execute([$id]);
        $existingBook = $stmt->fetch(PDO::FETCH_ASSOC);
        

        if (!$existingBook) {
            echo json_encode(['message' => 'Book not found', 'success' => false, 'error' => 'Not Found']);
            exit();
        }

        // Update the book record in the database
        $stmt = $pdo->prepare('UPDATE audioBooks SET name = ? WHERE id = ?');
        $stmt->execute([$name, $id]);

        //echo json_encode(['message' => 'Book updated successfully', 'success' => true]);
        echo json_encode([
            "message" => "Book updated successfully",
            "success" => true,
            "result" => null,
            "error" => null
        ]);
        exit();

    } catch (PDOException $e) {
        error_log("Error updating book: " . $e->getMessage());
        echo json_encode(['message' => 'Internal server error', 'success' => false, 'error' => 'Internal Server Error']);
        exit();
    }
}

// Update audio unit route (Protected) 
if ($requestUri === '/updateunit' && $requestMethod === 'POST') {   
    verifyToken($pdo); // Ensure user is authenticated
   error_log('bbbbbbbbbbbbbbbbbbbb');

   $id = $_POST['id'];
   $name=$_POST['name'];
   // Log the incoming data for debugging
   error_log('Updating units ID: ' . $id);
   error_log(json_encode($_POST));

   try {
       // Fetch the existing unic details
       $stmt = $pdo->prepare('SELECT * FROM units WHERE id = ?');
       $stmt->execute([$id]);
       $existingBook = $stmt->fetch(PDO::FETCH_ASSOC);
       

       if (!$existingBook) {
           echo json_encode(['message' => 'Unit not found', 'success' => false, 'error' => 'Not Found']);
           exit();
       }

       // Update the book record in the database
       $stmt = $pdo->prepare('UPDATE units SET name = ? WHERE id = ?');
       $stmt->execute([$name, $id]);

       //echo json_encode(['message' => 'Unit updated successfully', 'success' => true]);
       echo json_encode([
           "message" => "Unit updated successfully",
           "success" => true,
           "result" => null,
           "error" => null
       ]);
       exit();

   } catch (PDOException $e) {
       error_log("Error updating unit: " . $e->getMessage());
       echo json_encode(['message' => 'Internal server error', 'success' => false, 'error' => 'Internal Server Error']);
       exit();
   }
}

// Update audio topic route (Protected)
if ($requestUri === '/updatetopic' && $requestMethod === 'POST') {   
    verifyToken($pdo); // Ensure user is authenticated
   error_log('bbbbbbbbbbbbbbbbbbbb');

   $id = $_POST['id'];
   $name=$_POST['name'];
   // Log the incoming data for debugging
   error_log('Updating topic ID: ' . $id);
   error_log(json_encode($_POST));

   try {
       // Fetch the existing topic details
       $stmt = $pdo->prepare('SELECT * FROM topics WHERE id = ?');
       $stmt->execute([$id]);
       $existingBook = $stmt->fetch(PDO::FETCH_ASSOC);
       

       if (!$existingBook) {
           echo json_encode(['message' => 'Topic not found', 'success' => false, 'error' => 'Not Found']);
           exit();
       }

       // Update the topic record in the database
       $stmt = $pdo->prepare('UPDATE topics SET name = ? WHERE id = ?');
       $stmt->execute([$name, $id]);

       //echo json_encode(['message' => 'Topic updated successfully', 'success' => true]);
       echo json_encode([
           "message" => "Topic updated successfully",
           "success" => true,
           "result" => null,
           "error" => null
       ]);
       exit();

   } catch (PDOException $e) {
       error_log("Error updating topic: " . $e->getMessage());
       echo json_encode(['message' => 'Internal server error', 'success' => false, 'error' => 'Internal Server Error']);
       exit();
   }
}

// Update audio
if ($requestUri === '/updateaudio' && $requestMethod === 'POST') { 
    verifyToken($pdo); // Ensure user is authenticated
    error_log('bbbbbbbbbbbbbbbbbbbb');

    $id = $_POST['id'];
    $audioText = $_POST['audioText'] ?? null;
    $audioName = $_POST['name'] ?? null;
    $audioFile = $_FILES['audio_file'] ?? null;

    // Log the incoming data for debugging
    error_log('Updating audio_files ID: ' . $id);
    error_log(json_encode($_POST));
    error_log(json_encode($_FILES));

    try {
        // Fetch the existing audio_files details
        $stmt = $pdo->prepare('SELECT * FROM audio_files WHERE id = ?');
        $stmt->execute([$id]);
        $existingBook = $stmt->fetch(PDO::FETCH_ASSOC);
        
       

        if (!$existingBook) {
            echo json_encode(['message' => 'audio file not found', 'success' => false, 'error' => 'Not Found']);
            exit();
        }

        // Check for duplicate audioFile if a new $audioFile is uploaded
        if ($audioFile) {
            $stmt = $pdo->prepare('SELECT * FROM audio_files WHERE name = ? AND id != ?');
            $stmt->execute([$audioName, $id]);
            $duplicatePdf = $stmt->fetch();

            if ($duplicatePdf) {
                echo json_encode(['message' => 'This audio files file already exists.', 'success' => false]);
                exit();
            }
        }

        // Define the upload directory
        $uploadDir = __DIR__ . '/uploads/audio/';

        // Handle old file deletion and set new filenames
       
        if ($audioFile && $existingBook['file_path']) {
            @unlink($uploadDir . $existingBook['file_path']);
        }

        // Sanitize the title for filenames
        $sanitizedTitle = preg_replace('/[^a-zA-Z0-9_-]/', '_', $audioName);
        $pdfFilename = $audioFile ? $sanitizedTitle . '.' . pathinfo($_FILES['audio_file']['name'], PATHINFO_EXTENSION) : $existingBook['file_path'];

        // Move uploaded files to the uploads directory
        if ($audioFile && !move_uploaded_file($_FILES['audio_file']['tmp_name'], $uploadDir . $pdfFilename)) {
            echo json_encode(['message' => 'Failed to upload PDF file', 'success' => false]);
            exit();
        }
        

        // Update the audio record in the database
        $stmt = $pdo->prepare('UPDATE audio_files SET audioText = ?, name = ?, file_path = ? WHERE id = ?');
        $stmt->execute([$audioText, $audioName, $pdfFilename, $id]);

        echo json_encode(['message' => 'Audio updated successfully', 'success' => true]);
        exit();
    } catch (PDOException $e) {
        error_log("Error updating audio: " . $e->getMessage());
        echo json_encode(['message' => 'Internal server error', 'success' => false, 'error' => 'Internal Server Error']);
        exit();
    }
}

// Update audio with type
if ($requestUri === '/updateaudiowithtype' && $requestMethod === 'POST') {
    verifyToken($pdo); // Ensure user is authenticated
    error_log('updateaudiowithtype');

    $id = $_POST['id'];
    $audioName = $_POST['name'] ?? 'unnamed_audio';
    $audioFile = $_FILES['audio_file'] ?? null;
    $category = $_POST['category'] ?? null;

    // Log the incoming data for debugging
    error_log('Updating audio_files ID: ' . $id);
    error_log(json_encode($_POST));
    error_log(json_encode($_FILES));

    try {
        // Fetch the existing audio file details
        $stmt = $pdo->prepare('SELECT * FROM audio_types WHERE id = ?');
        $stmt->execute([$id]);
        $existingAudio = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$existingAudio) {
            echo json_encode(['message' => 'Audio file not found', 'success' => false, 'error' => 'Not Found']);
            exit();
        }

        // Check for duplicate audio file if a new $audioFile is uploaded
        if ($audioFile) {
            $stmt = $pdo->prepare('SELECT * FROM audio_types WHERE name = ? AND category = ? AND id != ?');
            $stmt->execute([$audioName, $category, $id]);
            $duplicateAudio = $stmt->fetch();

            if ($duplicateAudio) {
                echo json_encode(['message' => 'This audio file already exists.', 'success' => false]);
                exit();
            }
        }

        // Define the upload directory
        $uploadDir = __DIR__ . '/uploads/audio/';

        // Handle old file deletion and set new filenames
        if ($audioFile && isset($existingAudio['file_path'])) {
            @unlink($uploadDir . $existingAudio['file_path']);
        }

        // Sanitize the title for filenames, handling non-Latin scripts
        $sanitizedTitle = preg_replace('/[^a-zA-Z0-9_-]/u', '_', $audioName); // 'u' makes it UTF-8 aware
        
        // Use the Transliterator library for transliteration
        $sanitizedTitle = Transliterator::transliterate($sanitizedTitle);

        // Ensure there's always some text for filename
        if (empty(trim($sanitizedTitle))) {
            $sanitizedTitle = 'audio_' . uniqid();
        } else {
            // Remove leading and trailing underscores
            $sanitizedTitle = trim($sanitizedTitle, '_');
            // If after trimming we're left with nothing or just one character, use a default
            if (strlen($sanitizedTitle) <= 1) {
                $sanitizedTitle = 'audio_' . uniqid();
            }
        }

        $audioFilename = $audioFile ? $sanitizedTitle . '.' . pathinfo($audioFile['name'], PATHINFO_EXTENSION) : $existingAudio['file_path'];

        // Move uploaded files to the uploads directory
        if ($audioFile && !move_uploaded_file($audioFile['tmp_name'], $uploadDir . $audioFilename)) {
            echo json_encode(['message' => 'Failed to upload audio file', 'success' => false]);
            exit();
        }

        // Update the audio record in the database
        $stmt = $pdo->prepare('UPDATE audio_types SET name = ?, category = ?, file_path = ? WHERE id = ?');
        $stmt->execute([$audioName, $category, $audioFilename, $id]);

        echo json_encode(['message' => 'Audio updated successfully', 'success' => true]);
        exit();
    } catch (PDOException $e) {
        error_log("Error updating audio: " . $e->getMessage());
        echo json_encode(['message' => 'Internal server error', 'success' => false, 'error' => 'Internal Server Error']);
        exit();
    }
}

// Delete audio
if ($requestUri === '/deleteaudio' && $requestMethod === 'POST') {
     
    verifyToken($pdo); 
    $id = $_POST['id'];

    try {
        $stmt = $pdo->prepare('SELECT * FROM audio_files WHERE id = ?');
        $stmt->execute([$id]);
        $audio = $stmt->fetch();

        if (!$audio) {
            echo json_encode(['message' => 'Audio not found', 'success' => false, 'error' => 'Not Found']);
            exit();
        }

        // Delete associated files
        $filePath = "uploads/audio/{$audio['file_path']}";

        if (file_exists($filePath)) unlink($filePath);

        $stmt = $pdo->prepare('DELETE FROM audio_files WHERE id = ?');
        $stmt->execute([$id]);

        echo json_encode(['message' => 'Audio deleted successfully', 'success' => true]);
        exit();
    } catch (Exception $e) {
        error_log($e->getMessage());
        echo json_encode(['message' => 'Internal server error', 'success' => false, 'error' => 'Internal Server Error']);
    }
    exit();
}

// Delete audio with type
if ($requestUri === '/deleteaudiowithtype' && $requestMethod === 'POST') {
     
    verifyToken($pdo); 
    $id = $_POST['id'];

    try {
        $stmt = $pdo->prepare('SELECT * FROM audio_types WHERE id = ?');
        $stmt->execute([$id]);
        $audio = $stmt->fetch();

        if (!$audio) {
            echo json_encode(['message' => 'Audio not found', 'success' => false, 'error' => 'Not Found']);
            exit();
        }

        // Delete associated files
        $filePath = "uploads/audio/{$audio['file_path']}";

        if (file_exists($filePath)) unlink($filePath);

        $stmt = $pdo->prepare('DELETE FROM audio_types WHERE id = ?');
        $stmt->execute([$id]);

        echo json_encode(['message' => 'Audio deleted successfully', 'success' => true]);
        exit();
    } catch (Exception $e) {
        error_log($e->getMessage());
        echo json_encode(['message' => 'Internal server error', 'success' => false, 'error' => 'Internal Server Error']);
    }
    exit();
}



///////////////////////////////////////////////////////////////////////////////////////////////////////////

// Add video route (Protected)
if ($requestUri === '/addvideo' && $requestMethod === 'POST') {
    verifyToken($pdo); // Ensure user is authenticated

    // Log incoming POST data and files for debugging
    error_log("POST /video endpoint hit.");
    error_log("Request URI: $requestUri");
    error_log(json_encode($_POST));

    error_log($_POST['videoCategory']);

    $name = $_POST['name'] ?? '';
    $videoLink = $_POST['videoLink'] ?? '';
    $videoCategory = $_POST['videoCategory'] ?? ''; // Corrected here

    if (empty($name) || empty($videoLink) || empty($videoCategory)) {
        echo json_encode(['message' => 'Missing required fields', 'success' => false]);
        exit();
    }
    
    // Check for duplicate videos in the database
    $stmt = $pdo->prepare('SELECT * FROM videos WHERE videoLink = ?');
    $stmt->execute([$videoLink]);
    $existingVideo = $stmt->fetch();

    if ($existingVideo) {
        echo json_encode(['message' => 'This video file already exists', 'success' => false]);
        exit();
    }

    // Insert new video record into the database
    $stmt = $pdo->prepare('INSERT INTO videos (name, videoLink, videoCategory) VALUES (?, ?, ?)');
    $stmt->execute([$name, $videoLink, $videoCategory]);
    echo json_encode(['message' => 'Video added successfully', 'success' => true]);
    exit();
}

// Get video route 
if ($requestUri === '/getvideos' && $requestMethod === 'GET') {
    error_log("GET /Videos endpoint hit.");

    // Get pagination parameters
    $page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
    $limit = isset($_GET['limit']) ? (int)$_GET['limit'] : 10;
    $offset = ($page - 1) * $limit;

    try {
        // Fetch total number of books
        $stmt = $pdo->prepare('SELECT COUNT(*) AS total FROM videos');
        $stmt->execute();
        $totalVideos = $stmt->fetch()['total'];
        
        // Log total number of Videos to the terminal
        error_log("Total number of videos: " . $totalVideos);

        // Fetch books with pagination
        $stmt = $pdo->prepare('SELECT * FROM videos LIMIT ? OFFSET ?');
        $stmt->bindValue(1, (int)$limit, PDO::PARAM_INT);
        $stmt->bindValue(2, (int)$offset, PDO::PARAM_INT);
        $stmt->execute();
        $videos = $stmt->fetchAll(PDO::FETCH_ASSOC);

        // Prepare the JSON response
        $response = [
            'message' => 'Videos retrieved successfully',
            'success' => true,
            'error' => null,
            'result' => [
                'total' => $totalVideos,
                'videos' => $videos,
                'currentPage' => $page,
                'totalPages' => ceil($totalVideos / $limit)
            ]
        ];

        // Log the response to the terminal
       // error_log(json_encode($response));
        
        // Respond with JSON
        echo json_encode($response);
        exit();

    } catch (PDOException $e) {
        // Prepare error response
        $errorResponse = json_encode([
            'message' => 'Internal server error',
            'success' => false,
            'error' => $e->getMessage(),
            'result' => null
        ]);

        // Log the error response to the terminal
        error_log($errorResponse);

        // Respond with the error JSON
        echo $errorResponse;
        exit();
    }
}

// Get  video Categorys
if ($requestUri === '/getvideoscategorys' && $requestMethod === 'GET') {

    // Log request details
    error_log("GET /getvideoscategorys endpoint hit.");

    try {
        // Fetch distinct, non-null categories
        $stmt = $pdo->prepare('SELECT DISTINCT LOWER(videoCategory) AS category FROM videos WHERE videoCategory IS NOT NULL');
        $stmt->execute();
        $categories = $stmt->fetchAll(PDO::FETCH_COLUMN); // Fetch as a flat array of category strings

        if (!empty($categories)) {
            echo json_encode(['message' => 'Categories fetched', 'success' => true, 'result' => $categories]);
        } else {
            echo json_encode(['message' => 'No categories found', 'success' => false, 'result' => []]);
        }
    } catch (PDOException $e) {
        // Log the error and respond with an error message
        error_log("Database error: " . $e->getMessage());
        echo json_encode([
            'message' => 'Internal server error',
            'success' => false,
            'error' => $e->getMessage(),
            'result' => null
        ]);
    }

    exit();
}

// Get video with Categorys route by pagination
if ($requestUri === '/getvideosbycategory' && $requestMethod === 'GET') {
    //verifyToken($pdo);
    error_log("GET /video by category endpoint hit.");
    error_log($_GET['videoCategory']);

    // Get pagination parameters
    $page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
    $limit = isset($_GET['limit']) ? (int)$_GET['limit'] : 10;
    $offset = ($page - 1) * $limit;
    $category = $_GET['videoCategory'] ?? null;

    try {
        // Fetch total number of `videos` entries with category
        $stmt = $pdo->prepare('SELECT COUNT(*) AS total FROM videos WHERE videoCategory = :category');
        $stmt->execute([':category' => $category]);
        $totalVideosByCategory = $stmt->fetch()['total'];
        
        // Log total number of videos to the terminal
        error_log("Total number of videos by category: " . $totalVideosByCategory);

        // Fetch `videoCategory` entries with pagination
        $stmt = $pdo->prepare('SELECT * FROM videos WHERE videoCategory = :category ORDER BY createdAt DESC LIMIT :limit OFFSET :offset');
        $stmt->bindValue(':category', $category, PDO::PARAM_STR);
        $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
        $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
        $stmt->execute();
        $videos = $stmt->fetchAll(PDO::FETCH_ASSOC);

        // Prepare the JSON response
        $response = [
            'message' => 'Videos retrieved successfully',
            'success' => true,
            'error' => null,
            'result' => [
                'total' => $totalVideosByCategory,
                'videos' => $videos,
                'currentPage' => $page,
                'totalPages' => ceil($totalVideosByCategory / $limit),
                'limit' => $limit
            ]
        ];

        // Respond with JSON
        echo json_encode($response);
        exit();

    } catch (PDOException $e) {
        // Prepare error response
        $errorResponse = [
            'message' => 'Internal server error',
            'success' => false,
            'error' => $e->getMessage(),
            'result' => null
        ];

        // Log the error response to the terminal
        error_log(json_encode($errorResponse));

        // Respond with the error JSON
        echo json_encode($errorResponse);
        exit();
    }
}

// Update video route (Protected)
if ($requestUri === '/updateVideo' && $requestMethod === 'POST') {   
    verifyToken($pdo); // Ensure user is authenticated
   

   $id = $_POST['id'];
   $name=$_POST['name'];
   $videoLink=$_POST['videoLink'];
   $videoCategory= $_POST['videoCategory'];
   // Log the incoming data for debugging
   error_log('Updating video ID: ' . $id);
   error_log(json_encode($_POST));

   try {
       // Fetch the existing topic details
       $stmt = $pdo->prepare('SELECT * FROM videos WHERE id = ?');
       $stmt->execute([$id]);
       $existingVideo = $stmt->fetch(PDO::FETCH_ASSOC);
       

       if (!$existingVideo) {
           echo json_encode(['message' => 'Video not found', 'success' => false, 'error' => 'Not Found']);
           exit();
       }

       // Update the topic record in the database
       $stmt = $pdo->prepare('UPDATE videos SET name = ? , videoLink = ? , videoCategory = ? WHERE id = ?');
       $stmt->execute([$name,$videoLink,$videoCategory, $id]);

       //echo json_encode(['message' => 'Topic updated successfully', 'success' => true]);
       echo json_encode([
           "message" => "Video updated successfully",
           "success" => true,
           "result" => null,
           "error" => null
       ]);
       exit();

   } catch (PDOException $e) {
       error_log("Error updating video: " . $e->getMessage());
       echo json_encode(['message' => 'Internal server error', 'success' => false, 'error' => 'Internal Server Error']);
       exit();
   }
}

// Delete video route (Protected)
if ($requestUri === '/deletevideo' && $requestMethod === 'POST') {
     
    verifyToken($pdo); 
    $id = $_POST['id'];

    try {
        $stmt = $pdo->prepare('SELECT * FROM videos WHERE id = ?');
        $stmt->execute([$id]);
        $videos = $stmt->fetch();

        if (!$videos) {
            echo json_encode(['message' => 'Video not found', 'success' => false, 'error' => 'Not Found']);
            exit();
        }

        $stmt = $pdo->prepare('DELETE FROM videos WHERE id = ?');
        $stmt->execute([$id]);

        echo json_encode(['message' => 'Videos deleted successfully', 'success' => true]);
        exit();
    } catch (Exception $e) {
        error_log($e->getMessage());
        echo json_encode(['message' => 'Internal server error', 'success' => false, 'error' => 'Internal Server Error']);
    }
    exit();
}


///////////////////////////////////////////////////////////////////////////////////////////////////////////

// Add ask fetwa route (Protected)
if ($requestUri === '/askfetwa' && $requestMethod === 'POST') {

    // Log incoming POST data and files for debugging
    error_log("POST /video endpoint hit.");
    error_log("Request URI: $requestUri");
    error_log(json_encode($_POST));

    $postText = $_POST['postText'];
    $posterId = $_POST['posterId'];

    if (!$postText || !$posterId) {
        echo json_encode(['message' => 'Missing required fields', 'success' => false]);
        exit();
    };
 
    
    // Insert new video record into the database
    $stmt = $pdo->prepare('INSERT INTO askFetwa (postText,posterId,pending) VALUES (?, ?,?)');
    $stmt->execute([$postText,$posterId,"yes"]);
    error_log('okkkkkkkkkk');
    echo json_encode(['message' => 'تم الإرسال بنجح', 'success' => true]);
    exit();
}

// get ask fetwa and anser fetwa by posterId route 
if ($requestUri === '/checkfetwa' && $requestMethod === 'GET') {

    try {
        // Get the posterId from the query parameters
        $posterId = isset($_GET['posterId']) ? $_GET['posterId'] : null;

        if (!$posterId) {
            echo json_encode([
                "message" => "posterId parameter is required",
                "success" => false,
                "result" => null,
                "error" => "Missing posterId parameter"
            ]);
            exit();
        }

        // Updated query to filter by `posterId`
        $stmt = $pdo->prepare("
            SELECT 
                a.id AS ask_id, 
                a.postText AS ask_post_text, 
                a.posterId AS ask_poster_id, 
                a.pending AS ask_pending, 
                a.createdAt AS ask_created_at,
                ans.id AS answer_id, 
                ans.answerTitle AS answer_title, 
                ans.postText AS answer_post_text, 
                ans.posterId AS answer_poster_id, 
                ans.createdAt AS answer_created_at
            FROM askFetwa a
            LEFT JOIN answerFetwa ans ON ans.askFetwa_id = a.id
            WHERE a.posterId = :posterId
            ORDER BY a.id, ans.id;
        ");

        // Bind the posterId parameter to the query
        $stmt->bindParam(':posterId', $posterId, PDO::PARAM_STR);
        $stmt->execute();

        // Organize data into a hierarchical structure
        $asks = [];
        while ($row = $stmt->fetch()) {
            $askId = $row['ask_id'];
            if (!isset($asks[$askId])) {
                $asks[$askId] = [
                    "id" => $askId,
                    "postText" => $row['ask_post_text'],
                    "posterId" => $row['ask_poster_id'],
                    "pending" => $row['ask_pending'],
                    "createdAt" => $row['ask_created_at'],
                    "answers" => []
                ];
            }

            if (!empty($row['answer_id'])) {
                $asks[$askId]['answers'][] = [
                    "id" => $row['answer_id'],
                    "answerTitle" => $row['answer_title'], // Include `answerTitle`
                    "postText" => $row['answer_post_text'],
                    "posterId" => $row['answer_poster_id'],
                    "createdAt" => $row['answer_created_at']
                ];
            }
        }

        // Convert associative arrays to indexed arrays for JSON response
        $result = array_values($asks);
        // Send the JSON response
        echo json_encode([
            "message" => "askFetwa retrieved successfully",
            "success" => true,
            "result" => $result,
            "error" => null
        ]);

        exit();

    } catch (PDOException $e) {
        // Handle errors
        echo json_encode([
            "message" => "Failed to retrieve askFetwa",
            "success" => false,
            "result" => null,
            "error" => $e->getMessage()
        ]);
        exit();
    }
}

// get asked fetwa
if ($requestUri === '/getaskedfetwa' && $requestMethod === 'GET') {
    verifyToken($pdo);
    error_log("GET /getaskfetwa endpoint hit.");

    // Get pagination parameters
    $page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
    $limit = isset($_GET['limit']) ? (int)$_GET['limit'] : 10;
    $offset = ($page - 1) * $limit;

    try {
        // Fetch total number of `askFetwa` entries with pending = 'yes'
        $stmt = $pdo->prepare('SELECT COUNT(*) AS total FROM askFetwa WHERE pending = "yes"');
        $stmt->execute();
        $totalAskFetwa = $stmt->fetch()['total'];
        
        // Log total number of askFetwa to the terminal
        error_log("Total number of askFetwa: " . $totalAskFetwa);

        // Fetch `askFetwa` entries with pagination
        $stmt = $pdo->prepare('SELECT * FROM askFetwa WHERE pending = "yes" ORDER BY createdAt DESC LIMIT ? OFFSET ?');
        $stmt->bindValue(1, (int)$limit, PDO::PARAM_INT);
        $stmt->bindValue(2, (int)$offset, PDO::PARAM_INT);
        $stmt->execute();
        $askFetwa = $stmt->fetchAll(PDO::FETCH_ASSOC);

        // Prepare the JSON response
        $response = [
            'message' => 'askFetwa retrieved successfully',
            'success' => true,
            'error' => null,
            'result' => [
                'total' => $totalAskFetwa,
                'askFetwa' => $askFetwa,
                'currentPage' => $page,
                'totalPages' => ceil($totalAskFetwa / $limit)
            ]
        ];

        // Respond with JSON
        echo json_encode($response);
        exit();

    } catch (PDOException $e) {
        // Prepare error response
        $errorResponse = json_encode([
            'message' => 'Internal server error',
            'success' => false,
            'error' => $e->getMessage(),
            'result' => null
        ]);

        // Log the error response to the terminal
        error_log($errorResponse);

        // Respond with the error JSON
        echo $errorResponse;
        exit();
    }
}

// geting all answered fetwas
if ($requestUri === '/getansweredfetwas' && $requestMethod === 'GET') {
    error_log("GET /answerfetwa endpoint hit.");

    try {
        // Pagination parameters
        $page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
        $limit = isset($_GET['limit']) ? (int)$_GET['limit'] : 10;
        $offset = ($page - 1) * $limit;

        // Query to fetch paginated data
        $stmt = $pdo->prepare("
            SELECT id, answerTitle, postText, posterId, createdAt
            FROM answerFetwa
            ORDER BY createdAt DESC
            LIMIT :limit OFFSET :offset
        ");
        $stmt->bindParam(':limit', $limit, PDO::PARAM_INT);
        $stmt->bindParam(':offset', $offset, PDO::PARAM_INT);
        $stmt->execute();

        $data = $stmt->fetchAll(PDO::FETCH_ASSOC);

        // Get total count for pagination
        $countStmt = $pdo->query("SELECT COUNT(*) AS total FROM answerFetwa");
        $total = $countStmt->fetchColumn();

        echo json_encode([
            "message" => "Answers fetched successfully",
            "success" => true,
            "result" => $data,
            "total" => $total,
            "page" => $page,
            "limit" => $limit
        ]);
        exit();

    } catch (PDOException $e) {
        echo json_encode([
            "message" => "Failed to fetch answers",
            "success" => false,
            "result" => null,
            "error" => $e->getMessage()
        ]);
        exit();
    }
}

// get answered fetwas by pagination
if ($requestUri === '/getansweredfetwasbypagination' && $requestMethod === 'GET') {
    verifyToken($pdo);
    error_log("GET /answerFetwa endpoint hit.");

    // Get pagination parameters
    $page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
    $limit = isset($_GET['limit']) ? (int)$_GET['limit'] : 10;
    $offset = ($page - 1) * $limit;

    try {
        // Fetch total number of `askFetwa` entries with pending = 'yes'
        $stmt = $pdo->prepare('SELECT COUNT(*) AS total FROM answerFetwa');
        $stmt->execute();
        $totalAskFetwa = $stmt->fetch()['total'];
        
        // Log total number of askFetwa to the terminal
        error_log("Total number of askFetwa: " . $totalAskFetwa);

        // Fetch `askFetwa` entries with pagination
        $stmt = $pdo->prepare('SELECT * FROM answerFetwa ORDER BY createdAt DESC LIMIT ? OFFSET ?');
        $stmt->bindValue(1, (int)$limit, PDO::PARAM_INT);
        $stmt->bindValue(2, (int)$offset, PDO::PARAM_INT);
        $stmt->execute();
        $askFetwa = $stmt->fetchAll(PDO::FETCH_ASSOC);

        // Prepare the JSON response
        $response = [
            'message' => 'answered fetwas retrieved successfully',
            'success' => true,
            'error' => null,
            'result' => [
                'total' => $totalAskFetwa,
                'askFetwa' => $askFetwa,
                'currentPage' => $page,
                'totalPages' => ceil($totalAskFetwa / $limit)
            ]
        ];

        // Respond with JSON
        echo json_encode($response);
        exit();

    } catch (PDOException $e) {
        // Prepare error response
        $errorResponse = json_encode([
            'message' => 'Internal server error',
            'success' => false,
            'error' => $e->getMessage(),
            'result' => null
        ]);

        // Log the error response to the terminal
        error_log($errorResponse);

        // Respond with the error JSON
        echo $errorResponse;
        exit();
    }
}

// Add an answer route (Protected)
if ($requestUri === '/addanswer' && $requestMethod === 'POST') {
    verifyToken($pdo); // Ensure user is authenticated

    // Log incoming POST data and files for debugging
    error_log("POST /addanswer endpoint hit.");
    error_log("Request URI: $requestUri");
    error_log(json_encode($_POST));

    $questionId = $_POST['questionId'];
    $askerId = $_POST['askerId'];
    $answerTitle = $_POST['answerTitle'];
    $answerText = $_POST['answerText'];

    if (!$questionId || !$askerId || !$answerTitle || !$answerText) {
        echo json_encode(['message' => 'Missing required fields', 'success' => false]);
        exit();
    }

    try {
        // Start a transaction
        $pdo->beginTransaction();

        // Check for duplicate videos in the database
        $stmt = $pdo->prepare('SELECT * FROM answerFetwa WHERE askFetwa_id = ?');
        $stmt->execute([$questionId]);
        $existingAnswer = $stmt->fetch();

         if ( $existingAnswer) {
        echo json_encode(['message' => 'This answer exists', 'success' => false]);
        exit();
        }

        // Insert the new answer into the `answerFetwa` table
        $stmt = $pdo->prepare('INSERT INTO answerFetwa (answerTitle, postText, posterId, askFetwa_id) VALUES (?, ?, ?, ?)');
        $stmt->execute([$answerTitle, $answerText, $askerId, $questionId]);

        // Update the `pending` field in the `askFetwa` table to "no" for the given question ID
        $updateStmt = $pdo->prepare('UPDATE askFetwa SET pending = ? WHERE id = ?');
        $updateStmt->execute(['no', $questionId]);

        // Commit the transaction
        $pdo->commit();

        // Respond with success message
        echo json_encode(['message' => 'Answer added successfully.', 'success' => true]);
        exit();
    } catch (Exception $e) {
        // Rollback the transaction in case of an error
        $pdo->rollBack();

        // Log the error
        error_log("Error adding answer or updating askFetwa: " . $e->getMessage());

        // Respond with an error message
        echo json_encode(['message' => 'Failed to add answer or update question status.', 'success' => false]);
        exit();
    }
}

// Add an answer with out question route (Protected)
if ($requestUri === '/addanswerwithoutquestion' && $requestMethod === 'POST') {
    verifyToken($pdo); // Ensure user is authenticated

    // Log incoming POST data and files for debugging
    error_log("POST /addanswer endpoint hit.");
    error_log("Request URI: $requestUri");
    error_log(json_encode($_POST));

    
    $answerTitle = $_POST['answerTitle'];
    $answerText = $_POST['answerText'];

    if (!$answerTitle || !$answerText) {
        echo json_encode(['message' => 'Missing required fields', 'success' => false]);
        exit();
    }

    try {
        // Start a transaction
        $pdo->beginTransaction();

        // Insert the new answer into the `answerFetwa` table
        $stmt = $pdo->prepare('INSERT INTO answerFetwa (answerTitle, postText, posterId, askFetwa_id) VALUES (?, ?, ?, ?)');
        $stmt->execute([$answerTitle, $answerText, '', '']);

        // Commit the transaction
        $pdo->commit();

        // Respond with success message
        echo json_encode(['message' => 'Answer added successfully.', 'success' => true]);
        exit();
    } catch (Exception $e) {
        // Rollback the transaction in case of an error
        $pdo->rollBack();

        // Log the error
        error_log("Error adding answer or updating askFetwa: " . $e->getMessage());

        // Respond with an error message
        echo json_encode(['message' => 'Failed to add answer or update question status.', 'success' => false]);
        exit();
    }
}

// Update answer route (Protected) 
if ($requestUri === '/updateanswer' && $requestMethod === 'POST') {   
    verifyToken($pdo); // Ensure user is authenticated

   $id = $_POST['id'];
   $answerTitle=$_POST['answerTitle'];
   $answerText=$_POST['answerText'];
   // Log the incoming data for debugging
   error_log('Updating answer ID: ' . $id);
   error_log(json_encode($_POST));

   try {
       // Fetch the existing book details
       $stmt = $pdo->prepare('SELECT * FROM answerFetwa WHERE id = ?');
       $stmt->execute([$id]);
       $existingAnswer = $stmt->fetch(PDO::FETCH_ASSOC);
       

       if (!$existingAnswer) {
           echo json_encode(['message' => 'Answer not found', 'success' => false, 'error' => 'Not Found']);
           exit();
       }

       // Update the answer record in the database
       $stmt = $pdo->prepare('UPDATE answerFetwa SET answerTitle = ? ,postText = ? WHERE id = ?');
       $stmt->execute([$answerTitle,$answerText,$id]);

       echo json_encode([
           "message" => "Answer updated successfully",
           "success" => true,
           "result" => null,
           "error" => null
       ]);
       exit();

   } catch (PDOException $e) {
       error_log("Error updating answer: " . $e->getMessage());
       echo json_encode(['message' => 'Internal server error', 'success' => false, 'error' => 'Internal Server Error']);
       exit();
   }
}


// Delete answer route (Protected)
if ($requestUri === '/deleteanswer' && $requestMethod === 'POST') {
     
    verifyToken($pdo); 
    $id = $_POST['id'];
    $questionId = $_POST['questionId'];

    try {
        $pdo->beginTransaction();

        $stmt = $pdo->prepare('SELECT * FROM answerFetwa WHERE id = ?');
        $stmt->execute([$id]);
        $answer = $stmt->fetch();

        if (!$answer) {
            echo json_encode(['message' => 'Answer not found', 'success' => false, 'error' => 'Not Found']);
            exit();
        }

        // Update the `pending` field in the `askFetwa` table to "yes" for the given question ID
        if($questionId){
            $updateStmt = $pdo->prepare('UPDATE askFetwa SET pending = ? WHERE id = ?');
            $updateStmt->execute(['yes', $questionId]);
        }
        
        $stmt = $pdo->prepare('DELETE FROM answerFetwa WHERE id = ?');
        $stmt->execute([$id]); 

        $pdo->commit();

        echo json_encode(['message' => 'Answer deleted successfully', 'success' => true]);
        exit();
    } catch (Exception $e) {
        $pdo->rollBack(); // Rollback transaction on error
        error_log($e->getMessage());
        echo json_encode(['message' => 'Internal server error', 'success' => false, 'error' => 'Internal Server Error']);
        exit();
    }
    exit();
}



?>







