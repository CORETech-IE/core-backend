// Defines routes related to authentication (e.g., login endpoint)
import express from 'express';
import { login } from '../controllers/authController';
import { loginLimiter } from '../middlewares/rateLimiter';


const router = express.Router();

// POST /auth/login → returns a signed JWT
router.post('/login', loginLimiter, login);

export default router;
