// Hardened Node.js Express app with common security protections applied

const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');
const { execFile } = require('child_process');

const app = express();

const requestLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    standardHeaders: true,
    legacyHeaders: false
});

app.use(requestLimiter);
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

const db = mysql.createConnection({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'security_lab'
});

db.connect((err) => {
    if (err) {
        console.error('Database connection failed:', err);
    } else {
        console.log('Connected to database');
    }
});

const escapeHtml = (unsafe) => {
    if (typeof unsafe !== 'string') {
        return '';
    }

    return unsafe
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
};

// Login endpoint using email/password (parameterized query with hashed passwords)
app.post('/login', (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).send('Email and password are required');
    }

    const query = 'SELECT id, email, password FROM users WHERE email = ?';
    db.query(query, [email], async (err, results) => {
        if (err) {
            return res.status(500).send('Database error');
        }

        if (results.length === 0) {
            return res.status(401).send('Invalid credentials');
        }

        try {
            const user = results[0];
            if (!user.password) {
                return res.status(401).send('Invalid credentials');
            }
            const isMatch = await bcrypt.compare(password, user.password);
            if (isMatch) {
                return res.send('Login successful');
            }
            return res.status(401).send('Invalid credentials');
        } catch (compareError) {
            return res.status(500).send('Error validating credentials');
        }
    });
});

app.get('/profile', (req, res) => {
    const name = escapeHtml(req.query.name || '');
    res.send(`<h1>Welcome, ${name}</h1>`);
});

// Simple demonstration endpoint for returning a one-time random token
// Note: tokens are not persisted or tied to a specific session/user
app.get('/token', (req, res) => {
    const token = crypto.randomBytes(32).toString('hex');
    res.send(`Your token: ${token}`);
});

app.get('/user/:id', (req, res) => {
    const userId = req.params.id;
    const sql = 'SELECT * FROM users WHERE id = ?';
    db.query(sql, [userId], (err, results) => {
        if (err) {
            return res.status(500).send('Database error');
        }
        res.json(results);
    });
});

const allowedCommands = {
    uptime: { cmd: 'uptime', args: [] },
    whoami: { cmd: 'whoami', args: [] }
};

app.post('/run', (req, res) => {
    const { command } = req.body;
    const commandConfig = allowedCommands[command];

    if (!commandConfig) {
        return res.status(400).send('Command not allowed');
    }

    execFile(commandConfig.cmd, commandConfig.args, { timeout: 5000 }, (error, stdout, stderr) => {
        if (error) {
            return res.status(500).send(`Command failed: ${stderr}`);
        }
        res.send(stdout);
    });
});

const SAFE_BASE_PATH = path.resolve(__dirname, 'safe_files');
if (!fs.existsSync(SAFE_BASE_PATH)) {
    fs.mkdirSync(SAFE_BASE_PATH, { recursive: true });
}

app.get('/read-file', (req, res) => {
    const filePath = req.query.path;
    if (!filePath) {
        return res.status(400).send('Path is required');
    }

    const resolvedPath = path.resolve(SAFE_BASE_PATH, filePath);
    if (!resolvedPath.startsWith(SAFE_BASE_PATH)) {
        return res.status(400).send('Invalid path');
    }

    fs.readFile(resolvedPath, 'utf8', (err, data) => {
        if (err) {
            if (err.code === 'ENOENT') {
                return res.status(404).send('File not found');
            }
            return res.status(500).send('Unable to read file');
        }
        res.send(data);
    });
});

app.listen(3000, () => {
    console.log('Secure app listening on port 3000');
});
