const pool = require('../config/db');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

function makeToken(id, role) {
    return jwt.sign({ id, role }, process.env.JWT_SECRET, {
        expiresIn: process.env.JWT_EXPIRES_IN || '1d'
    });
}

exports.registerUser = async (req, res) => {
    try {
        const fullName = typeof req.body.full_name === 'string' ? req.body.full_name.trim() : '';
        const email = typeof req.body.email === 'string' ? req.body.email.trim().toLowerCase() : '';
        const password = typeof req.body.password === 'string' ? req.body.password : '';

        if (!fullName || !email || !password) {
            return res.status(400).json({ message: 'full_name, email, and password are required' });
        }
        if (fullName.length > 100) {
            return res.status(400).json({ message: 'Full name must be 100 characters or fewer' });
        }
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 150) {
            return res.status(400).json({ message: 'Please provide a valid email address' });
        }
        if (password.length < 8) {
            return res.status(400).json({ message: 'Password must contain at least 8 characters' });
        }

        const [existing] = await pool.execute('SELECT id FROM users WHERE email = ?', [email]);
        if (existing.length) {
            return res.status(409).json({ message: 'Email is already registered' });
        }

        const hash = await bcrypt.hash(password, 10);
        const [result] = await pool.execute(
            'INSERT INTO users (full_name, email, password) VALUES (?, ?, ?)',
            [fullName, email, hash]
        );

        return res.status(201).json({
            message: 'User registered successfully',
            user: { id: result.insertId, full_name: fullName, email }
        });
    } catch (error) {
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({ message: 'Email is already registered' });
        }
        console.error('Registration error:', error.message);
        return res.status(500).json({ message: 'Internal server error' });
    }
};

exports.loginUser = async (req, res) => {
    try {
        const email = typeof req.body.email === 'string' ? req.body.email.trim().toLowerCase() : '';
        const password = typeof req.body.password === 'string' ? req.body.password : '';

        if (!email || !password) {
            return res.status(400).json({ message: 'Email and password are required' });
        }

        const [rows] = await pool.execute(
            'SELECT id, full_name, email, password FROM users WHERE email = ?',
            [email]
        );
        if (!rows.length || !(await bcrypt.compare(password, rows[0].password))) {
            return res.status(401).json({ message: 'Invalid email or password' });
        }

        const user = rows[0];
        return res.json({
            message: 'Login successful',
            token: makeToken(user.id, 'user'),
            user: { id: user.id, full_name: user.full_name, email: user.email, role: 'user' }
        });
    } catch (error) {
        console.error('User login error:', error.message);
        return res.status(500).json({ message: 'Internal server error' });
    }
};

exports.getMyProfile = async (req, res) => {
    try {
        const [rows] = await pool.execute(
            'SELECT id, full_name, email, phone, address, created_at, updated_at FROM users WHERE id = ?',
            [req.auth.id]
        );
        if (!rows.length) return res.status(404).json({ message: 'User not found' });
        return res.json({ user: rows[0] });
    } catch (error) {
        console.error('Get profile error:', error.message);
        return res.status(500).json({ message: 'Internal server error' });
    }
};

exports.updateMyProfile = async (req, res) => {
    try {
        const allowed = ['full_name', 'phone', 'address'];
        const updates = [];
        const values = [];

        for (const field of allowed) {
            if (Object.prototype.hasOwnProperty.call(req.body, field)) {
                if (req.body[field] !== null && typeof req.body[field] !== 'string') {
                    return res.status(400).json({ message: `${field} must be a string or null` });
                }
                if (field === 'full_name' && (!req.body[field] || !req.body[field].trim())) {
                    return res.status(400).json({ message: 'full_name cannot be empty' });
                }
                const max = field === 'full_name' ? 100 : (field === 'phone' ? 20 : 255);
                if (typeof req.body[field] === 'string' && req.body[field].length > max) {
                    return res.status(400).json({ message: `${field} must be ${max} characters or fewer` });
                }
                updates.push(`${field} = ?`);
                values.push(typeof req.body[field] === 'string' ? req.body[field].trim() : null);
            }
        }

        if (!updates.length) {
            return res.status(400).json({ message: 'Provide full_name, phone, or address to update' });
        }

        values.push(req.auth.id);
        const [result] = await pool.execute(
            `UPDATE users SET ${updates.join(', ')} WHERE id = ?`,
            values
        );
        if (!result.affectedRows) return res.status(404).json({ message: 'User not found' });

        const [rows] = await pool.execute(
            'SELECT id, full_name, email, phone, address, created_at, updated_at FROM users WHERE id = ?',
            [req.auth.id]
        );
        return res.json({ message: 'Profile updated successfully', user: rows[0] });
    } catch (error) {
        console.error('Update profile error:', error.message);
        return res.status(500).json({ message: 'Internal server error' });
    }
};
