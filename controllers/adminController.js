const pool = require('../config/db');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

exports.loginAdmin = async (req, res) => {
    try {
        const email = typeof req.body.email === 'string' ? req.body.email.trim().toLowerCase() : '';
        const password = typeof req.body.password === 'string' ? req.body.password : '';

        if (!email || !password) {
            return res.status(400).json({ message: 'Email and password are required' });
        }

        const [rows] = await pool.execute(
            'SELECT id, full_name, email, password FROM admins WHERE email = ?',
            [email]
        );
        if (!rows.length || !(await bcrypt.compare(password, rows[0].password))) {
            return res.status(401).json({ message: 'Invalid email or password' });
        }

        const admin = rows[0];
        const token = jwt.sign(
            { id: admin.id, role: 'admin' },
            process.env.JWT_SECRET,
            { expiresIn: process.env.JWT_EXPIRES_IN || '1d' }
        );

        return res.json({
            message: 'Admin login successful',
            token,
            admin: { id: admin.id, full_name: admin.full_name, email: admin.email, role: 'admin' }
        });
    } catch (error) {
        return res.status(500).json({ message: 'Internal server error' });
    }
};

exports.getMyAdminProfile = async (req, res) => {
    try {
        const [rows] = await pool.execute(
            'SELECT id, full_name, email, created_at, updated_at FROM admins WHERE id = ?',
            [req.auth.id]
        );
        if (!rows.length) return res.status(404).json({ message: 'Admin not found' });
        return res.json({ admin: rows[0] });
    } catch (error) {
        return res.status(500).json({ message: 'Internal server error' });
    }
};

exports.updateMyAdminProfile = async (req, res) => {
    try {
        const updates = [];
        const values = [];

        if (Object.prototype.hasOwnProperty.call(req.body, 'full_name')) {
            const name = req.body.full_name;
            if (typeof name !== 'string' || !name.trim() || name.trim().length > 100) {
                return res.status(400).json({ message: 'full_name must be a non-empty string of at most 100 characters' });
            }
            updates.push('full_name = ?');
            values.push(name.trim());
        }

        if (!updates.length) {
            return res.status(400).json({ message: 'Provide full_name to update' });
        }

        values.push(req.auth.id);
        const [result] = await pool.execute(
            `UPDATE admins SET ${updates.join(', ')} WHERE id = ?`,
            values
        );
        if (!result.affectedRows) return res.status(404).json({ message: 'Admin not found' });

        const [rows] = await pool.execute(
            'SELECT id, full_name, email, created_at, updated_at FROM admins WHERE id = ?',
            [req.auth.id]
        );
        return res.json({ message: 'Admin profile updated successfully', admin: rows[0] });
    } catch (error) {
        return res.status(500).json({ message: 'Internal server error' });
    }
};


exports.listUsers = async (req, res) => {
    try {
        const [rows] = await pool.execute(
            'SELECT id, full_name, email, phone, address, created_at, updated_at FROM users ORDER BY id DESC'
        );
        return res.json({ count: rows.length, users: rows });
    } catch (error) {
        return res.status(500).json({ message: 'Internal server error' });
    }
};


exports.getUserById = async (req, res) => {
    try {
        const id = Number(req.params.id);
        if (!Number.isSafeInteger(id) || id < 1) {
            return res.status(400).json({ message: 'User ID must be a positive integer' });
        }
        const [rows] = await pool.execute(
            'SELECT id, full_name, email, phone, address, created_at, updated_at FROM users WHERE id = ?',
            [id]
        );
        if (!rows.length) return res.status(404).json({ message: 'User not found' });
        return res.json({ user: rows[0] });
    } catch (error) {
        return res.status(500).json({ message: 'Internal server error' });
    }
};

exports.updateUserById = async (req, res) => {
    try {
        const id = Number(req.params.id);
        if (!Number.isSafeInteger(id) || id < 1) {
            return res.status(400).json({ message: 'User ID must be a positive integer' });
        }

        const allowed = ['full_name', 'phone', 'address'];
        const updates = [];
        const values = [];

        for (const field of allowed) {
            if (Object.prototype.hasOwnProperty.call(req.body, field)) {
                const value = req.body[field];
                if (value !== null && typeof value !== 'string') {
                    return res.status(400).json({ message: `${field} must be a string or null` });
                }
                if (field === 'full_name' && (typeof value !== 'string' || !value.trim())) {
                    return res.status(400).json({ message: 'full_name cannot be empty' });
                }
                const max = field === 'full_name' ? 100 : (field === 'phone' ? 20 : 255);
                if (typeof value === 'string' && value.length > max) {
                    return res.status(400).json({ message: `${field} must be ${max} characters or fewer` });
                }
                updates.push(`${field} = ?`);
                values.push(typeof value === 'string' ? value.trim() : null);
            }
        }

        if (!updates.length) {
            return res.status(400).json({ message: 'Provide full_name, phone, or address to update' });
        }

        values.push(id);
        const [result] = await pool.execute(
            `UPDATE users SET ${updates.join(', ')} WHERE id = ?`,
            values
        );
        if (!result.affectedRows) return res.status(404).json({ message: 'User not found' });

        const [rows] = await pool.execute(
            'SELECT id, full_name, email, phone, address, created_at, updated_at FROM users WHERE id = ?',
            [id]
        );
        return res.json({ message: 'User profile updated successfully', user: rows[0] });
    } catch (error) {
        return res.status(500).json({ message: 'Internal server error' });
    }
};

exports.deleteUserById = async (req, res) => {
    try {
        const id = Number(req.params.id);
        if (!Number.isSafeInteger(id) || id < 1) {
            return res.status(400).json({ message: 'User ID must be a positive integer' });
        }

        const [result] = await pool.execute('DELETE FROM users WHERE id = ?', [id]);
        if (!result.affectedRows) return res.status(404).json({ message: 'User not found' });

        return res.json({ message: 'User deleted successfully', user_id: id });
    } catch (error) {
        return res.status(500).json({ message: 'Internal server error' });
    }
};
