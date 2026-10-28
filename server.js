require('dotenv').config();

const express = require('express');
const pool = require('./config/db');
const userRoutes = require('./routes/userRoutes');
const adminRoutes = require('./routes/adminRoutes');

const app = express();
app.use(express.json({ limit: '20kb' }));

app.get('/', (req, res) => {
    res.json({ message: 'Role-Based Profile API is running!' });
});

app.use('/api/users', userRoutes);
app.use('/api/admins', adminRoutes);


app.use((req, res) => {
    res.status(404).json({ message: 'Route not found' });
});


app.use((err, req, res, next) => {
    res.status(500).json({ message: 'Internal server error' });
});

async function startServer() {
    if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) {
        process.exit(1);
    }

    try {
        const connection = await pool.getConnection();
        connection.release();

        const port = Number(process.env.PORT) || 5000;
        app.listen(port);
    } catch {
        process.exit(1);
    }
}

startServer();
