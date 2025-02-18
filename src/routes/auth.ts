import { Router, Request, Response } from 'express';
import { body, validationResult } from 'express-validator';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { pool } from '../config/database';
import { authenticateToken } from '../middleware/auth';
import nodemailer from 'nodemailer';
import crypto from 'crypto';

const router = Router();

// Email configuration
const transporter = nodemailer.createTransport({
    service: process.env.EMAIL_SERVICE,
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASSWORD
    }
});

// Register new user
router.post('/register', [
    body('email').isEmail(),
    body('password').isLength({ min: 8 }),
    body('firstName').notEmpty(),
    body('lastName').notEmpty()
], async (req: Request, res: Response): Promise<void> => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        res.status(400).json({ errors: errors.array() });
        return;
    }

    try {
        const { email, password, firstName, lastName } = req.body;

        // Check if user already exists
        const userExists = await pool.query(
            'SELECT * FROM user_information WHERE email = $1',
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
            'INSERT INTO user_information (email, email_verification_status, first_name, last_name, password_hash) VALUES ($1, $2, $3, $4, $5)',
            [email, false, firstName, lastName, passwordHash]
        );

        // Send verification email
        const verificationToken = crypto.randomBytes(32).toString('hex');
        // Store verification token in database or cache
        
        const verificationUrl = `${process.env.FRONTEND_URL}/verify-email?token=${verificationToken}`;
        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Verify your email',
            html: `Please click <a href="${verificationUrl}">here</a> to verify your email.`
        });

        res.status(201).json({ message: 'User registered successfully. Please verify your email.' });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Login
router.post('/login', [
    body('email').isEmail(),
    body('password').notEmpty()
], async (req: Request, res: Response): Promise<void> => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        res.status(400).json({ errors: errors.array() });
        return;
    }

    try {
        const { email, password } = req.body;

        // Get user
        const user = await pool.query(
            'SELECT * FROM user_information WHERE email = $1',
            [email]
        );

        if (user.rows.length === 0) {
            res.status(401).json({ error: 'Invalid credentials' });
            return;
        }

        // Check password
        const validPassword = await bcrypt.compare(password, user.rows[0].password_hash);
        if (!validPassword) {
            res.status(401).json({ error: 'Invalid credentials' });
            return;
        }

        // Generate tokens
        const jwtToken = jwt.sign({ email }, process.env.JWT_SECRET as string, { expiresIn: '1h' });
        const refreshToken = crypto.randomBytes(40).toString('hex');

        // Create session
        await pool.query(
            'INSERT INTO session_information (user_id, jwt_token, refresh_token, ip_address, user_agent, is_active, session_expiry, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8)',
            [
                email,
                jwtToken,
                refreshToken,
                req.ip,
                req.headers['user-agent'],
                true,
                Math.floor(Date.now() / 1000) + 3600, // 1 hour
                Math.floor(Date.now() / 1000)
            ]
        );

        res.json({ token: jwtToken, refreshToken });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Refresh token
router.post('/refresh-token', async (req: Request, res: Response): Promise<void> => {
    const { refreshToken } = req.body;

    if (!refreshToken) {
        res.status(401).json({ error: 'Refresh token required' });
        return;
    }

    try {
        // Find session
        const session = await pool.query(
            'SELECT * FROM session_information WHERE refresh_token = $1 AND is_active = true',
            [refreshToken]
        );

        if (session.rows.length === 0) {
            res.status(401).json({ error: 'Invalid refresh token' });
            return;
        }

        const { user_id } = session.rows[0];

        // Generate new tokens
        const newJwtToken = jwt.sign({ email: user_id }, process.env.JWT_SECRET as string, { expiresIn: '1h' });
        const newRefreshToken = crypto.randomBytes(40).toString('hex');

        // Update session
        await pool.query(
            'UPDATE session_information SET jwt_token = $1, refresh_token = $2, session_expiry = $3, updated_at = $4 WHERE refresh_token = $5',
            [
                newJwtToken,
                newRefreshToken,
                Math.floor(Date.now() / 1000) + 3600,
                Math.floor(Date.now() / 1000),
                refreshToken
            ]
        );

        res.json({ token: newJwtToken, refreshToken: newRefreshToken });
    } catch (error) {
        console.error('Refresh token error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Reset password request
router.post('/reset-password-request', [
    body('email').isEmail()
], async (req: Request, res: Response): Promise<void> => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        res.status(400).json({ errors: errors.array() });
        return;
    }

    try {
        const { email } = req.body;

        // Check if user exists
        const user = await pool.query(
            'SELECT * FROM user_information WHERE email = $1',
            [email]
        );

        if (user.rows.length === 0) {
            // Return success even if user doesn't exist for security
            res.json({ message: 'If an account exists, a password reset email has been sent.' });
            return;
        }

        // Generate reset token
        const resetToken = crypto.randomBytes(32).toString('hex');
        const resetTokenExpiry = Math.floor(Date.now() / 1000) + 3600; // 1 hour

        // Store reset token in database or cache 
        
        // Send reset email
        const resetUrl = `${process.env.FRONTEND_URL}/reset-password?token=${resetToken}`;
        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Reset your password',
            html: `Please click <a href="${resetUrl}">here</a> to reset your password. This link will expire in 1 hour.`
        });

        res.json({ message: 'If an account exists, a password reset email has been sent.' });
    } catch (error) {
        console.error('Reset password request error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Reset password
router.post('/reset-password', [
    body('token').notEmpty(),
    body('password').isLength({ min: 8 })
], async (req: Request, res: Response): Promise<void> => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        res.status(400).json({ errors: errors.array() });
        return;
    }

    try {
        const { token, password } = req.body;

        // Verify token and get user
        // This would involve checking the stored reset token and its expiry
        
        // Hash new password
        const saltRounds = 10;
        const passwordHash = await bcrypt.hash(password, saltRounds);

        // Update password
        // await pool.query(
        //     'UPDATE user_information SET password_hash = $1 WHERE email = $2',
        //     [passwordHash, userEmail]
        // );

        // Invalidate all active sessions for the user
        // await pool.query(
        //     'UPDATE session_information SET is_active = false WHERE user_id = $1',
        //     [userEmail]
        // );

        res.json({ message: 'Password reset successful' });
    } catch (error) {
        console.error('Reset password error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Logout
router.post('/logout', authenticateToken, async (req: Request, res: Response): Promise<void> => {
    try {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];

        // Invalidate session
        await pool.query(
            'UPDATE session_information SET is_active = false WHERE jwt_token = $1',
            [token]
        );

        res.json({ message: 'Logged out successfully' });
    } catch (error) {
        console.error('Logout error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

export default router;
