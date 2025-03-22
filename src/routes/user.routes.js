const express = require('express');
const router = express.Router();
const authMiddleware = require('../middleware');
const userController = require('../controllers/user.controller');

// User Routes
router.post('/signup', userController.signup);
router.post('/login', userController.login);
router.get('/profile', authMiddleware.verifyToken, userController.getProfile);
router.put('/edit', authMiddleware.verifyToken, userController.editProfile);
router.delete('/delete', authMiddleware.verifyToken, userController.deleteProfile);

module.exports = router;
