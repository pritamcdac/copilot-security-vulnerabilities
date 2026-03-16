// Intentionally vulnerable Node.js Express app for security scanner testing
// Vulnerabilities included:
// 1. Hardcoded database credentials
// 2. Reflected XSS in user profile endpoint
// 3. Password stored in plaintext
// 4. Insecure random token generation using Math.random()

const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql');

const app = express();
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// 1. Hardcoded database credentials (VULNERABLE)
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'password123', // Hardcoded credentials
    database: 'security_lab'
});

db.connect((err) => {
    if (err) {
        console.error('Database connection failed:', err);
    } else {
        console.log('Connected to database');
    }
});

// Login endpoint using email/password (parameterized query)
app.post('/login', (req, res) => {
    const { email, password } = req.body;
    const query = 'SELECT * FROM users WHERE email = ? AND password = ?';
    db.query(query, [email, password], (err, results) => {
        if (err) {
            return res.status(500).send('Database error');
        }
        if (results.length > 0) {
            // 3. Password stored in plaintext (VULNERABLE)
            // Passwords are compared as plaintext, not hashed
            res.send('Login successful');
        } else {
            res.send('Invalid credentials');
        }
    });
});

// 2. Reflected XSS in user profile endpoint (VULNERABLE)
app.get('/profile', (req, res) => {
    const name = req.query.name;
    // Vulnerable to reflected XSS
    res.send(`<h1>Welcome, ${name}</h1>`);
});

// 4. Insecure random token generation using Math.random() (VULNERABLE)
app.get('/token', (req, res) => {
    // Insecure token generation
    const token = Math.random().toString(36).substring(2);
    res.send(`Your token: ${token}`);
});

app.listen(3000, () => {
    console.log('Vulnerable app listening on port 3000');
});
