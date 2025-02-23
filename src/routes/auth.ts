import { Router, Request, Response, NextFunction } from 'express';
import { body, validationResult } from 'express-validator';
import bcrypt from 'bcrypt';
import jwt, { Secret } from 'jsonwebtoken';
import { pool } from '../config/database';
import { authenticateToken } from '../middleware/auth';
import nodemailer from 'nodemailer';
import crypto from 'crypto';

// Validate required environment variables
if (!process.env.JWT_SECRET || !process.env.JWT_REFRESH_SECRET) {
    throw new Error('JWT_SECRET and JWT_REFRESH_SECRET must be set in environment variables');
}

const router = Router();

// Email configuration
const transporter = nodemailer.createTransport({
    service: process.env.EMAIL_SERVICE,
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASSWORD
    }
});

// Generate random 6-digit code
const generateVerificationCode = (): string => {
    return Math.floor(100000 + Math.random() * 900000).toString();
};

// Send verification email
const sendVerificationEmail = async (email: string, code: string) => {
    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'SafeNest Email Verification',
        html: `
            <h1>Email Verification</h1>
            <p>Your verification code is: <strong>${code}</strong></p>
            <p>This code will expire in 15 minutes.</p>
        `
    };

    await transporter.sendMail(mailOptions);
};

// Register new user
router.post('/register', [
    body('email').isEmail(),
    body('password').isLength({ min: 8 }),
    body('firstName').notEmpty(),
    body('lastName').notEmpty()
], async (req: Request, res: Response, next: NextFunction) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            res.status(400).json({ errors: errors.array() });
            return;
        }

        const { email, password, firstName, lastName } = req.body;

        // Check if user already exists
        const userExists = await pool.query(
            'SELECT email FROM users WHERE email = $1',
            [email]
        );

        if (userExists.rows.length > 0) {
            res.status(400).json({ error: 'User already exists' });
            return;
        }

        // Hash password
        const saltRounds = 10;
        const passwordHash = await bcrypt.hash(password, saltRounds);

        // Create user
        await pool.query(
            'INSERT INTO users (email, email_verification_status, first_name, last_name, password_hash) VALUES ($1, $2, $3, $4, $5)',
            [email, false, firstName, lastName, passwordHash]
        );

        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        next(error);
    }
});

// Login user
router.post('/login', [
    body('email').isEmail(),
    body('password').exists()
], async (req: Request, res: Response, next: NextFunction) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            res.status(400).json({ errors: errors.array() });
            return;
        }

        const { email, password } = req.body;

        // Get user
        const result = await pool.query(
            'SELECT email, first_name, last_name, email_verification_status, password_hash FROM users WHERE email = $1',
            [email]
        );

        if (result.rows.length === 0) {
            res.status(401).json({ error: 'Invalid credentials' });
            return;
        }

        const user = result.rows[0];

        // Verify password
        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) {
            res.status(401).json({ error: 'Invalid credentials' });
            return;
        }

        // Generate tokens
        const token = jwt.sign(
            { email: user.email },
            process.env.JWT_SECRET || '',
            { expiresIn: Number(process.env.JWT_EXPIRATION) || 3600 }
        );
        const refreshToken = jwt.sign(
            { email: user.email },
            process.env.JWT_REFRESH_SECRET || '',
            { expiresIn: Number(process.env.JWT_REFRESH_EXPIRATION) || 604800 }
        );

        // Store session
        await pool.query(
            'INSERT INTO sessions (user_id, jwt_token, refresh_token, ip_address, user_agent, session_expiry, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)',
            [
                user.email,
                token,
                refreshToken,
                req.ip,
                req.headers['user-agent'],
                Date.now() + (Number(process.env.JWT_EXPIRATION) || 3600) * 1000, // Convert seconds to milliseconds
                Date.now(),
                Date.now()
            ]
        );

        res.json({
            token,
            refreshToken,
            user: {
                firstName: user.first_name,
                lastName: user.last_name,
                emailVerified: user.email_verification_status
            }
        });
    } catch (error) {
        next(error);
    }
});

// Logout user
router.post('/logout', authenticateToken, async (req: Request, res: Response, next: NextFunction) => {
    try {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];

        // Invalidate session
        await pool.query(
            'UPDATE sessions SET is_active = false WHERE jwt_token = $1',
            [token]
        );

        res.json({ message: 'Logged out successfully' });
    } catch (error) {
        next(error);
    }
});

// Refresh token
router.post('/refresh', async (req: Request, res: Response, next: NextFunction) => {
    try {
        const { refreshToken } = req.body;

        if (!refreshToken) {
            res.status(401).json({ error: 'Refresh token required' });
            return;
        }

        const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET || '') as { email: string };
        const email = decoded.email;

        // Get session
        const sessionResult = await pool.query(
            'SELECT * FROM sessions WHERE user_id = $1 AND refresh_token = $2',
            [email, refreshToken]
        );

        if (sessionResult.rows.length === 0) {
            res.status(401).json({ error: 'Invalid refresh token' });
            return;
        }

        // Generate new tokens
        const newToken = jwt.sign(
            { email },
            process.env.JWT_SECRET || '',
            { expiresIn: Number(process.env.JWT_EXPIRATION) || 3600 }
        );

        const newRefreshToken = jwt.sign(
            { email },
            process.env.JWT_REFRESH_SECRET || '',
            { expiresIn: Number(process.env.JWT_REFRESH_EXPIRATION) || 604800 }
        );

        // Update session
        await pool.query(
            'UPDATE sessions SET jwt_token = $1, refresh_token = $2, updated_at = $3 WHERE user_id = $4 AND refresh_token = $5',
            [
                newToken, 
                newRefreshToken, 
                Math.floor(Date.now() / 1000), 
                email, 
                refreshToken
            ]
        );

        res.json({
            token: newToken,
            refreshToken: newRefreshToken
        });
    } catch (error) {
        next(error);
    }
});

// Get current user endpoint
router.get('/me', async (req: Request, res: Response, next: NextFunction) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader) {
            res.status(401).json({ error: 'No token provided' });
            return;
        }

        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, process.env.JWT_SECRET || '') as { email: string };
        
        // Get user data
        const result = await pool.query(
            'SELECT email, first_name, last_name, email_verification_status FROM users WHERE email = $1',
            [decoded.email]
        );

        if (result.rows.length === 0) {
            res.status(401).json({ error: 'User not found' });
            return;
        }

        const user = result.rows[0];
        res.json({
            user: {
                email: user.email,
                firstName: user.first_name,
                lastName: user.last_name,
                emailVerified: user.email_verification_status
            }
        });
    } catch (error) {
        if (error instanceof jwt.JsonWebTokenError) {
            res.status(401).json({ error: 'Invalid token' });
            return;
        }
        next(error);
    }
});

// Verify token endpoint
router.get('/verify', authenticateToken, async (req: Request, res: Response) => {
    try {
        const userEmail = (req as any).user?.email;
        
        if (!userEmail) {
            res.status(401).json({ valid: false });
            return;
        }

        const result = await pool.query(
            'SELECT email, first_name, last_name, email_verification_status FROM users WHERE email = $1',
            [userEmail]
        );

        if (result.rows.length === 0) {
            res.status(401).json({ valid: false });
            return;
        }

        const user = result.rows[0];
        
        res.json({ 
            valid: true,
            user: {
                email: user.email,
                firstName: user.first_name,
                lastName: user.last_name,
                emailVerified: user.email_verification_status
            }
        });
    } catch (error) {
        console.error('Error verifying token:', error);
        res.status(500).json({ error: 'Failed to verify token' });
    }
});

// Resend verification code endpoint
router.post('/resend-verification', async (req: Request, res: Response, next: NextFunction) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader) {
            res.status(401).json({ error: 'No token provided' });
            return;
        }

        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, process.env.JWT_SECRET || '') as { email: string };
        const email = decoded.email;

        // Generate new verification code
        const code = generateVerificationCode();
        const now = Math.floor(Date.now() / 1000);
        const expiresAt = now + (15 * 60); // 15 minutes from now

        // Delete any existing unused codes for this user
        await pool.query(
            'DELETE FROM email_verifications WHERE email = $1 AND is_used = FALSE',
            [email]
        );

        // Store new verification code
        await pool.query(
            'INSERT INTO email_verifications (email, code, created_at, expires_at) VALUES ($1, $2, $3, $4)',
            [email, code, now, expiresAt]
        );

        // Send verification email
        await sendVerificationEmail(email, code);

        res.json({ message: 'Verification code sent' });
    } catch (error) {
        next(error);
    }
});

// Verify email code endpoint
router.post('/verify-email', async (req: Request, res: Response, next: NextFunction) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader) {
            res.status(401).json({ error: 'No token provided' });
            return;
        }

        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, process.env.JWT_SECRET || '') as { email: string };
        const email = decoded.email;
        const { code } = req.body;

        if (!code) {
            res.status(400).json({ error: 'Verification code is required' });
            return;
        }

        const now = Math.floor(Date.now() / 1000);

        // Get the latest unused verification code
        const result = await pool.query(
            'SELECT * FROM email_verifications WHERE email = $1 AND code = $2 AND is_used = FALSE AND expires_at > $3 ORDER BY created_at DESC LIMIT 1',
            [email, code, now]
        );

        if (result.rows.length === 0) {
            res.status(400).json({ error: 'Invalid or expired verification code' });
            return;
        }

        // Mark code as used
        await pool.query(
            'UPDATE email_verifications SET is_used = TRUE WHERE id = $1',
            [result.rows[0].id]
        );

        // Update user's email verification status
        await pool.query(
            'UPDATE users SET email_verification_status = TRUE WHERE email = $1',
            [email]
        );

        res.json({ verified: true });
    } catch (error) {
        next(error);
    }
});

export default router;
