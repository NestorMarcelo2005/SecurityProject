<?php
// Enable all error reporting for development
error_reporting(E_ALL);
ini_set('display_errors', 1);
// Main analysis function that processes submitted code
function analyzeCode($code, $language, $filename = '') {
    $lines = explode("\n", $code);              // Split the code into individual lines
    $lineCount = count($lines);                 // Count total number of lines

    // Initialize the result structure
    $result = [
        'language' => $language,
        'filename' => $filename,
        'line_count' => $lineCount,
        'vulnerabilities' => [],                // List of detected vulnerabilities
        'warnings' => [],                       // Any general warnings (like unsupported language)
        'stats' => [                            // Count of vulnerabilities by severity
            'critical' => 0,
            'high' => 0,
            'medium' => 0,
            'low' => 0,
            'safe' => 1                         // Assume safe unless vulnerabilities are found
        ]
    ];

    // Map each language to its specific vulnerability detection function
    $detectors = [
        'php' => 'detectPhpVulnerabilities',
        'html' => 'detectHtmlVulnerabilities',
        'javascript' => 'detectJsVulnerabilities',
        'python' => 'detectPythonVulnerabilities',
        'java' => 'detectJavaVulnerabilities',
        'c' => 'detectCVulnerabilities',
        'cpp' => 'detectCppVulnerabilities',
        'csharp' => 'detectCsharpVulnerabilities'
    ];

    // Check if the language is supported, and call the appropriate detector
    if (isset($detectors[$language]) && function_exists($detectors[$language])) {
        $detector = $detectors[$language];
        $result = $detector($lines, $result);
    } else {
        // If the language is not supported, log a warning
        $result['warnings'][] = [
            'title' => 'Unsupported Language',
            'description' => 'This language is not fully supported for security scanning',
            'line' => 0,
            'code_snippet' => '',
            'recommendation' => 'Consider using a supported language or perform manual security review'
        ];
    }

    // Mark the code as not fully safe if any vulnerability or warning is found
    if (!empty($result['vulnerabilities']) || !empty($result['warnings'])) {
        $result['stats']['safe'] = 0;
    }

    return $result;
}

//Function to detect vulnerabilities using regex patterns
function detectVulnerabilities($lines, $patterns, $result) {
    foreach ($lines as $lineNum => $line) {
        $lineNum++;                                  // Convert to 1-based line numbering
        $trimmedLine = trim($line);                  // Clean the line of leading/trailing whitespace

        foreach ($patterns as $pattern) {
            $hasMatch = preg_match($pattern['regex'], $line); // Apply main pattern
            $hasExclude = isset($pattern['regex_exclude']) &&
                          preg_match($pattern['regex_exclude'], $line); // Optional exclusion pattern

            if ($hasMatch && !$hasExclude) {
                // If a match is found and not excluded, create a vulnerability entry
                $vuln = [
                    'title' => $pattern['title'],
                    'severity' => $pattern['severity'],
                    'description' => $pattern['description'],
                    'line' => $lineNum,
                    'code_snippet' => $trimmedLine,
                    'recommendation' => $pattern['recommendation'],
                    'owasp' => $pattern['owasp'] ?? 'OWASP Reference'
                ];

                // Add vulnerability and update stats
                $result['vulnerabilities'][] = $vuln;
                $result['stats'][strtolower($pattern['severity'])]++;
                $result['stats']['safe'] = 0;
            }
        }
    }
    return $result;
}

// Detector for PHP-specific vulnerabilities
function detectPhpVulnerabilities($lines, $result) {
    // List of vulnerability patterns to search in PHP code
    $patterns = [
        [
            'regex' => '/\b(mysqli_query|mysql_query|pg_query|sqlite_query|exec|query|prepare)\s*\(.*\$\w+.*\)/i',
            'regex_exclude' => '/\b(mysqli_query|mysql_query|pg_query|sqlite_query)\s*\(\s*\$?\w+\s*,\s*"[^"]*"\s*\)/i',
            'title' => 'SQL Injection',
            'severity' => 'CRITICAL',
            'description' => 'Direct variable usage in SQL query without prepared statements',
            'recommendation' => 'Use prepared statements with parameterized queries (PDO or mysqli)',
            'owasp' => 'A1:2017-Injection'
        ],
        [
            'regex' => '/(echo|print|<\?=)\s*[^;]*\$\w+/i',
            'regex_exclude' => '/htmlspecialchars|htmlentities/i',
            'title' => 'XSS Vulnerability',
            'severity' => 'HIGH',
            'description' => 'Unescaped output of user-controlled data',
            'recommendation' => 'Use htmlspecialchars() or htmlentities() with ENT_QUOTES and UTF-8',
            'owasp' => 'A7:2017-Cross-Site Scripting (XSS)'
        ],
        [
            'regex' => '/<form[^>]*method=["\']?post["\']?[^>]*>(?!.*(csrf|token|hidden)).*<\/form>/is',
            'title' => 'Potential CSRF Vulnerability',
            'severity' => 'MEDIUM',
            'description' => 'Form with POST method lacks visible CSRF token input field',
            'recommendation' => 'Include a hidden CSRF token input and verify it on form submission',
            'owasp' => 'A5:2017-Broken Access Control'
        ],
        [
            'regex' => '/\b(eval|assert|create_function)\s*\(/i',
            'title' => 'Code Injection',
            'severity' => 'CRITICAL',
            'description' => 'Dangerous function allowing execution of arbitrary code',
            'recommendation' => 'Avoid using eval() and similar functions with user input',
            'owasp' => 'A1:2017-Injection'
        ],
        [
            'regex' => '/\b(exec|shell_exec|system|passthru|proc_open)\s*\(.*\$\w+.*\)/i',
            'title' => 'Command Injection',
            'severity' => 'CRITICAL',
            'description' => 'System command execution with user-controlled input',
            'recommendation' => 'Use escapeshellarg() and avoid direct command execution with user input',
            'owasp' => 'A1:2017-Injection'
        ],
        [
            'regex' => '/\b(file_get_contents|file|readfile|include|require)\s*\(.*\$\w+.*\)/i',
            'title' => 'Path Traversal/LFI',
            'severity' => 'HIGH',
            'description' => 'File operations with user-controlled path',
            'recommendation' => 'Validate and sanitize file paths, use basename()',
            'owasp' => 'A5:2017-Broken Access Control'
        ],
        [
            'regex' => '/\b(move_uploaded_file)\s*\(/i',
            'title' => 'File Upload Risks',
            'severity' => 'HIGH',
            'description' => 'File upload handling without proper validation',
            'recommendation' => 'Validate file type, extension, and content; store outside web root',
            'owasp' => 'A5:2017-Broken Access Control'
        ],
        [
            'regex' => '/\b(md5|sha1)\s*\(/i',
            'regex_exclude' => '/hash_equals/',
            'title' => 'Insecure Hashing',
            'severity' => 'MEDIUM',
            'description' => 'Use of weak hashing algorithms for sensitive data',
            'recommendation' => 'Use password_hash() or Argon2 for password storage',
            'owasp' => 'A2:2017-Broken Authentication'
        ],
        [
            'regex' => '/\$\_(GET|POST|REQUEST|COOKIE|SERVER)\s*\[/i',
            'regex_exclude' => '/(isset|empty|htmlspecialchars|htmlentities|filter_var|intval|test_input)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)\s*\[|\$_SERVER\["REQUEST_METHOD"\]/i',
            'title' => 'Direct Superglobal Usage',
            'severity' => 'MEDIUM',
            'description' => 'User input used without validation or sanitization',
            'recommendation' => 'Always validate and sanitize user input with filter_var()',
            'owasp' => 'A1:2017-Injection'
        ],
        [
            'regex' => '/header\s*\(.*Location:\s*\$\w+/i',
            'title' => 'Open Redirect',
            'severity' => 'MEDIUM',
            'description' => 'Redirect using user-controlled input',
            'recommendation' => 'Validate redirect URLs against a whitelist',
            'owasp' => 'A10:2017-Unvalidated Redirects and Forwards'
        ],
        [
            'regex' => '/\b(openssl_random_pseudo_bytes|random_bytes|bin2hex)\s*\(/i',
            'title' => 'Secure Randomness',
            'severity' => 'LOW',
            'description' => 'Proper cryptographically secure random function usage',
            'recommendation' => 'Good practice for generating secure tokens',
            'owasp' => 'A2:2017-Broken Authentication'
        ]
    ];

    // Call the shared detection engine with the list of PHP patterns
    return detectVulnerabilities($lines, $patterns, $result);
}


// Detector for C-specific vulnerabilities
function detectCVulnerabilities($lines, $result) {
    // List of vulnerability patterns to search in C code
    $patterns = [
        [
            // Detect unsafe string functions that can cause buffer overflows
            'regex' => '/strcpy|strcat|gets/i',
            'title' => 'Buffer Overflow Risk',
            'severity' => 'CRITICAL',
            'description' => 'Use of unsafe string functions can lead to buffer overflows',
            'recommendation' => 'Use safer alternatives like strncpy, strncat, fgets',
            'owasp' => 'A9:2017-Using Components with Known Vulnerabilities'
        ],
        [
            // Detect use of system() which can lead to command injection
            'regex' => '/system\s*\(.*\)/i',
            'title' => 'Command Injection',
            'severity' => 'CRITICAL',
            'description' => 'System call may execute dangerous user-controlled commands',
            'recommendation' => 'Avoid system(); validate and sanitize inputs',
            'owasp' => 'A1:2017-Injection'
        ]
    ];
    // Call the shared detection engine with the list of C patterns
    return detectVulnerabilities($lines, $patterns, $result);
}
// Detector for C++-specific vulnerabilities
function detectCppVulnerabilities($lines, $result) {
    // List of vulnerability patterns to search in C++ code
    $patterns = [
        [
            // Detect unsafe string functions that can cause buffer overflows
            'regex' => '/strcpy|strcat|gets/i',
            'title' => 'Buffer Overflow Risk',
            'severity' => 'CRITICAL',
            'description' => 'Unsafe string manipulation may lead to buffer overflow',
            'recommendation' => 'Use std::string or safer functions like strncpy',
            'owasp' => 'A9:2017-Using Components with Known Vulnerabilities'
        ],
        [
            // Detect use of system() which can lead to command injection
            'regex' => '/system\s*\(.*\)/i',
            'title' => 'Command Injection',
            'severity' => 'CRITICAL',
            'description' => 'Use of system() can lead to OS command injection',
            'recommendation' => 'Avoid system calls with user input',
            'owasp' => 'A1:2017-Injection'
        ],
        [
            // Detect dynamic array allocation without bounds checking
            'regex' => '/new\s+[^\s]+\[\d+\]/i',
            'title' => 'Memory Allocation without Bounds Check',
            'severity' => 'MEDIUM',
            'description' => 'Array allocations should have bounds checked',
            'recommendation' => 'Ensure size is validated before dynamic allocation',
            'owasp' => 'A5:2017-Broken Access Control'
        ]
    ];
    // Call the shared detection engine with the list of C++ patterns
    return detectVulnerabilities($lines, $patterns, $result);
}
// Detector for C#-specific vulnerabilities
function detectCsharpVulnerabilities($lines, $result) {
    // List of vulnerability patterns to search in C# code
    $patterns = [
        [
            // Detect SQL queries built via string concatenation
            'regex' => '/SqlCommand\s*\(.*\+.*\)/i',
            'title' => 'SQL Injection',
            'severity' => 'CRITICAL',
            'description' => 'Concatenated SQL queries may allow SQL injection',
            'recommendation' => 'Use parameterized queries with SqlCommand.Parameters',
            'owasp' => 'A1:2017-Injection'
        ],
        [
            // Detect use of Process.Start which can lead to command injection
            'regex' => '/Process\.Start\s*\(.*\)/i',
            'title' => 'Command Injection',
            'severity' => 'CRITICAL',
            'description' => 'Executing shell commands can lead to security risks',
            'recommendation' => 'Avoid user input in Process.Start arguments',
            'owasp' => 'A1:2017-Injection'
        ],
        [
            // Detect direct assignment of Request data to ViewBag/ViewData
            'regex' => '/ViewBag|ViewData\s*\[.*\]\s*=\s*Request/i',
            'title' => 'Reflected XSS',
            'severity' => 'HIGH',
            'description' => 'Directly assigning Request data to views may lead to XSS',
            'recommendation' => 'Use Html.Encode and validate user input before rendering',
            'owasp' => 'A7:2017-Cross-Site Scripting (XSS)'
        ]
    ];
    // Call the shared detection engine with the list of C# patterns
    return detectVulnerabilities($lines, $patterns, $result);
}
// Detector for HTML-specific vulnerabilities
function detectHtmlVulnerabilities($lines, $result) {
    // List of vulnerability patterns to search in HTML code
    $patterns = [
        [
            // Detect inline event handlers with user input (potential XSS)
            'regex' => '/<\w+\s+[^>]*(on\w+)\s*=\s*["\']?[^"\'>]*\$\{?[a-zA-Z0-9_]+\}?[^"\'>]*["\']?/i',
            'title' => 'XSS (Inline Event Handler)',
            'severity' => 'HIGH',
            'description' => 'Unsanitized user input in event handler',
            'recommendation' => 'Avoid inline event handlers with user input',
            'owasp' => 'A7:2017-Cross-Site Scripting (XSS)'
        ],
        [
            // Detect user input inside <script> tags (potential XSS)
            'regex' => '/<script[^>]*>[^<]*\$\{?[a-zA-Z0-9_]+\}?[^<]*<\/script>/i',
            'title' => 'XSS (Script Tag)',
            'severity' => 'CRITICAL',
            'description' => 'Unsanitized user input inside script tag',
            'recommendation' => 'Sanitize all user input used in JavaScript contexts',
            'owasp' => 'A7:2017-Cross-Site Scripting (XSS)'
        ],
        [
            // Detect user input in href/src attributes (potential XSS)
            'regex' => '/<[^>]*(href|src)\s*=\s*["\']?[^"\'>]*\$\{?[a-zA-Z0-9_]+\}?[^"\'>]*["\']?/i',
            'title' => 'XSS (Attribute Injection)',
            'severity' => 'MEDIUM',
            'description' => 'Unsanitized user input in attribute',
            'recommendation' => 'Validate and sanitize all URLs and attribute values',
            'owasp' => 'A7:2017-Cross-Site Scripting (XSS)'
        ],
        [
            // Detect <iframe> usage (potential clickjacking risk)
            'regex' => '/<iframe[^>]*>/i',
            'title' => 'Clickjacking Risk',
            'severity' => 'MEDIUM',
            'description' => 'Iframe usage without proper security headers',
            'recommendation' => 'Set X-Frame-Options header to prevent clickjacking',
            'owasp' => 'A6:2017-Security Misconfiguration'
        ],
        [
            // Detect forms using GET method (potential data exposure)
            'regex' => '/<form[^>]*(method\s*=\s*["\']?get["\']?)/i',
            'title' => 'Form with GET Method',
            'severity' => 'LOW',
            'description' => 'Sensitive data exposed in URL',
            'recommendation' => 'Use POST method for forms containing sensitive data',
            'owasp' => 'A3:2017-Sensitive Data Exposure'
        ],
        [
            // Detect password input fields missing autocomplete="off"
            'regex' => '/<input[^>]*(type\s*=\s*["\']?password["\']?)/i',
            'title' => 'Password Input',
            'severity' => 'LOW',
            'description' => 'Password input without autocomplete="off"',
            'recommendation' => 'Add autocomplete="off" to password fields',
            'owasp' => 'A2:2017-Broken Authentication'
        ]
    ];

    // Call the shared detection engine with the list of HTML patterns
    return detectVulnerabilities($lines, $patterns, $result);
}
// Detector for JavaScript-specific vulnerabilities
function detectJsVulnerabilities($lines, $result) {
    // List of vulnerability patterns to search in JavaScript code
    $patterns = [
        [
            // Detect assignment to innerHTML (potential DOM XSS)
            'regex' => '/\.innerHTML\s*=/i',
            'title' => 'DOM XSS',
            'severity' => 'HIGH',
            'description' => 'Direct HTML injection without sanitization',
            'recommendation' => 'Use textContent instead or sanitize with DOMPurify',
            'owasp' => 'A7:2017-Cross-Site Scripting (XSS)'
        ],
        [
            // Detect use of eval() (dangerous code execution)
            'regex' => '/eval\s*\(/i',
            'title' => 'Code Injection',
            'severity' => 'CRITICAL',
            'description' => 'Dangerous eval function with user input',
            'recommendation' => 'Avoid eval() with user-controlled input',
            'owasp' => 'A1:2017-Injection'
        ],
        [
            // Detect use of localStorage or sessionStorage for sensitive data
            'regex' => '/localStorage|sessionStorage/i',
            'title' => 'Client-side Storage',
            'severity' => 'MEDIUM',
            'description' => 'Sensitive data stored in client-side storage',
            'recommendation' => 'Avoid storing sensitive data in localStorage/sessionStorage',
            'owasp' => 'A3:2017-Sensitive Data Exposure'
        ],
        [
            // Detect insecure API calls (fetch, axios.get, $.ajax)
            'regex' => '/\bfetch\s*\(|axios\.get|\.ajax\s*\(/i',
            'title' => 'Insecure API Calls',
            'severity' => 'MEDIUM',
            'description' => 'Potential insecure API requests',
            'recommendation' => 'Implement proper authentication and CSRF protection',
            'owasp' => 'A2:2017-Broken Authentication'
        ],
        [
            // Detect console.log statements (debugging code)
            'regex' => '/console\.log\s*\(/i',
            'title' => 'Debugging Code',
            'severity' => 'LOW',
            'description' => 'Debugging statements left in production code',
            'recommendation' => 'Remove console logs before deploying to production',
            'owasp' => 'A3:2017-Sensitive Data Exposure'
        ]
    ];
    // Call the shared detection engine with the list of JavaScript patterns
    return detectVulnerabilities($lines, $patterns, $result);
}




// Detector for Python-specific vulnerabilities
function detectPythonVulnerabilities($lines, $result) {
    // List of vulnerability patterns to search in Python code
    $patterns = [
        [
            // Detect SQL queries using string formatting (potential SQL injection)
            'regex' => '/\b(execute|executemany)\s*\(.*\%s.*\)/i',
            'title' => 'SQL Injection',
            'severity' => 'CRITICAL',
            'description' => 'String formatting in SQL query',
            'recommendation' => 'Use parameterized queries with ? placeholders',
            'owasp' => 'A1:2017-Injection'
        ],
        [
            // Detect use of subprocess functions (potential command injection)
            'regex' => '/subprocess\.(run|call|Popen)/i',
            'title' => 'Command Injection',
            'severity' => 'CRITICAL',
            'description' => 'Shell command execution with user input',
            'recommendation' => 'Avoid shell=True and validate input',
            'owasp' => 'A1:2017-Injection'
        ]
    ];
    
    // Call the shared detection engine with the list of Python patterns
    return detectVulnerabilities($lines, $patterns, $result);
}

// Detector for Java-specific vulnerabilities
function detectJavaVulnerabilities($lines, $result) {
    // List of vulnerability patterns to search in Java code
    $patterns = [
        [
            // Detect use of Statement.executeQuery or createStatement (potential SQL injection)
            'regex' => '/Statement\.executeQuery|createStatement\(\)/i',
            'title' => 'SQL Injection',
            'severity' => 'CRITICAL',
            'description' => 'Dynamic SQL query without prepared statements',
            'recommendation' => 'Use PreparedStatement with parameterized queries',
            'owasp' => 'A1:2017-Injection'
        ],
        [
            // Detect use of Runtime.getRuntime().exec (potential command injection)
            'regex' => '/Runtime\.getRuntime\(\)\.exec\(/i',
            'title' => 'Command Injection',
            'severity' => 'CRITICAL',
            'description' => 'System command execution with user input',
            'recommendation' => 'Validate and sanitize all command inputs',
            'owasp' => 'A1:2017-Injection'
        ]
    ];
    
    // Call the shared detection engine with the list of Java patterns
    return detectVulnerabilities($lines, $patterns, $result);
}

// Check if the form has been submitted using POST
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $analysisResult = [];
    $language = '';
    
    // If code is pasted in the textarea
    if (isset($_POST['code']) && !empty($_POST['code'])) {
        $language = $_POST['language']; // Get selected language
        $code = $_POST['code']; // Get pasted code
            $analysisResult = analyzeCode($code, $language); // Analyze pasted code

    // If a code file is uploaded
    } elseif (isset($_FILES['codefile']) && $_FILES['codefile']['error'] === UPLOAD_ERR_OK) {
        $file = $_FILES['codefile'];
        $filename = $file['name'];
        $extension = pathinfo($filename, PATHINFO_EXTENSION);
        $code = file_get_contents($file['tmp_name']); // Read uploaded file content

        // Map file extensions to programming languages
        $languageMap = [
            'php' => 'php',
            'html' => 'html',
            'htm' => 'html',
            'js' => 'javascript',
            'py' => 'python',
            'java' => 'java',
            'c' => 'c',
            'cpp' => 'cpp',
            'cs' => 'csharp'
        ];
        
        $language = $languageMap[$extension] ?? 'unknown'; // Fallback to 'unknown' if unsupported
        $analysisResult = analyzeCode($code, $language, $filename); // Analyze uploaded code
    }
}
?>

<!-- HTML PART -->
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Code Security Verifier</title>
    <link rel="stylesheet" href="styles.css">
</head>
<body>
    <header>
        <div class="header-content">
            <h1>Code Security Verifier</h1>
            <p>Detect vulnerabilities in your source code</p>
        </div>
    </header>

    <div class="container">
        <!-- Tab selector -->
        <div class="tabs">
            <div class="tab active" onclick="switchTab('upload')">Upload File</div>
            <div class="tab" onclick="switchTab('paste')">Paste Code</div>
        </div>


        <!-- File Upload Tab -->
        <div id="upload-tab" class="tab-content active">
            <h2>Upload Code File</h2>
            <form method="POST" enctype="multipart/form-data">
                <div class="file-input">
                    <input type="file" name="codefile" id="codefile" required>
                    <p>Drag & drop or click to browse</p>
                    <p>Supported files: PHP, HTML, JS, PY, JAVA, C, CPP, C#</p>
                </div>
                <button type="submit" class="btn">Analyze File</button>
            </form>
        </div>

        <!-- Paste Code Tab -->
        <div id="paste-tab" class="tab-content">
            <h2>Paste Your Code</h2>
            <form method="POST">
                <select name="language" class="language-select" required>
                    <option value="">Select Language</option>
                    <option value="php">PHP</option>
                    <option value="html">HTML</option>
                    <option value="javascript">JavaScript</option>
                    <option value="python">Python</option>
                    <option value="java">Java</option>
                    <option value="c">C</option>
                    <option value="cpp">C++</option>
                    <option value="csharp">C#</option>
                </select>
                <textarea name="code" placeholder="Paste your code here..." required></textarea>
                <button type="submit" class="btn">Analyze Code</button>
            </form>
        </div>

        <!-- Display analysis results if available -->
        <?php if (!empty($analysisResult)): ?>
        <div class="report">
            <h2>Security Analysis Report</h2>
            <div class="summary">
                <p><strong>Language:</strong> <?= strtoupper($analysisResult['language']) ?></p>
                <p><strong>File:</strong> <?= $analysisResult['filename'] ?? 'Pasted code' ?></p>
                <p><strong>Lines scanned:</strong> <?= $analysisResult['line_count'] ?></p>

                <!-- Risk stats -->
                <div class="stats">
                    <div class="stat-box stat-critical">
                        <h3><?= $analysisResult['stats']['critical'] ?></h3>
                        <p>CRITICAL</p>
                    </div>
                    <div class="stat-box stat-high">
                        <h3><?= $analysisResult['stats']['high'] ?></h3>
                        <p>HIGH</p>
                    </div>
                    <div class="stat-box stat-medium">
                        <h3><?= $analysisResult['stats']['medium'] ?></h3>
                        <p>MEDIUM</p>
                    </div>
                    <div class="stat-box stat-low">
                        <h3><?= $analysisResult['stats']['low'] ?></h3>
                        <p>LOW</p>
                    </div>
                    <div class="stat-box stat-safe">
                        <h3><?= $analysisResult['stats']['safe'] ?></h3>
                        <p>SAFE</p>
                    </div>
                </div>

                <!-- Visual Risk Meter -->
                <?php 
                $riskLevel = min(100, max(0, 
                    $analysisResult['stats']['critical'] * 100 + 
                    $analysisResult['stats']['high'] * 50 + 
                    $analysisResult['stats']['medium'] * 25 + 
                    $analysisResult['stats']['low'] * 10
                )); 
                ?>
                <div class="risk-meter">
                    <div class="risk-level" style="width: <?= $riskLevel ?>%; background: <?= 
                        $riskLevel > 80 ? 'var(--critical)' : 
                        ($riskLevel > 60 ? 'var(--high)' : 
                        ($riskLevel > 40 ? 'var(--medium)' : 
                        ($riskLevel > 20 ? 'var(--low)' : '#2ecc71'))) ?>">
                    </div>
                </div>
                <p>Overall risk level: <?= 
                    $riskLevel > 80 ? 'CRITICAL' : 
                    ($riskLevel > 60 ? 'HIGH' : 
                    ($riskLevel > 40 ? 'MEDIUM' : 
                    ($riskLevel > 20 ? 'LOW' : 'SAFE'))) ?></p>
            </div>

            <!-- Detected vulnerabilities -->
            <?php if (!empty($analysisResult['vulnerabilities'])): ?>
                <h3>Detected Vulnerabilities</h3>
                <?php foreach ($analysisResult['vulnerabilities'] as $vuln): ?>
                    <div class="vulnerability <?= strtolower($vuln['severity']) ?>">
                        <h3>
                            <span class="severity-badge badge-<?= strtolower($vuln['severity']) ?>">
                                <?= $vuln['severity'] ?>
                            </span>
                            <?= $vuln['title'] ?>
                        </h3>
                        <p><?= $vuln['description'] ?></p>
                        <p><strong>Location:</strong> Line <?= $vuln['line'] ?></p>
                        <div class="code-snippet">
                            <pre><?= htmlspecialchars($vuln['code_snippet']) ?></pre>
                        </div>
                        <p><strong>Recommendation:</strong> <?= $vuln['recommendation'] ?></p>
                        <p><strong>OWASP Reference:</strong> <?= $vuln['owasp'] ?></p>
                    </div>
                <?php endforeach; ?>
            <?php else: ?>
                <!-- No vulnerabilities found -->
                <div class="vulnerability low">
                    <h3>No Security Vulnerabilities Found</h3>
                    <p>Good job! No vulnerabilities were detected.</p>
                    <p>Keep following security best practices and update dependencies regularly.</p>
                </div>
            <?php endif; ?>
        </div>
        <?php endif; ?>
    </div>

    <!-- Footer -->
    <footer>
        <div class="container">
            <p>Code Security Verifier | Information Security Fundamentals</p>
            <p>University of Maribor</p>
        </div>
    </footer>

    <!-- JavaScript for tab switching, etc. -->
    <script src="scripts.js"></script>
</body>
</html>

