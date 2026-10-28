const express = require('express');
const router = express.Router();

const adminController = require('../controllers/adminController');
const { authenticateToken, requireRole } = require('../middleware/authMiddleware');

router.post('/login', adminController.loginAdmin);

router.get('/me', authenticateToken, requireRole('admin'), adminController.getMyAdminProfile);
router.patch('/me', authenticateToken, requireRole('admin'), adminController.updateMyAdminProfile);

router.get('/users', authenticateToken, requireRole('admin'), adminController.listUsers);
router.get('/users/:id', authenticateToken, requireRole('admin'), adminController.getUserById);
router.patch('/users/:id', authenticateToken, requireRole('admin'), adminController.updateUserById);
router.delete('/users/:id', authenticateToken, requireRole('admin'), adminController.deleteUserById);

module.exports = router;
