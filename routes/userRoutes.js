const express = require('express');
const router = express.Router();

const userController = require('../controllers/userController');
const { authenticateToken, requireRole } = require('../middleware/authMiddleware');

router.post('/register', userController.registerUser);
router.post('/login', userController.loginUser);

router.get('/me', authenticateToken, requireRole('user'), userController.getMyProfile);
router.patch('/me', authenticateToken, requireRole('user'), userController.updateMyProfile);

module.exports = router;
