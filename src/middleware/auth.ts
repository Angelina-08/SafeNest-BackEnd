import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { pool } from '../config/database';

export interface AuthRequest extends Request {
    user?: {
        email: string;
    };
    headers: Request['headers'];
}

export const authenticateToken = async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        res.status(401).json({ error: 'Access token required' });
        return;
    }

    try {
        // First verify the token structure
        const decoded = jwt.verify(token, process.env.JWT_SECRET || '') as { email: string };
        
        // Then check if there's an active session with this token
        const currentTime = Date.now();
        const sessionResult = await pool.query(
            `SELECT * FROM sessions 
             WHERE jwt_token = $1 
             AND user_id = $2 
             AND is_active = TRUE 
             AND session_expiry > $3`,
            [token, decoded.email, currentTime]
        );

        if (sessionResult.rows.length === 0) {
            res.status(401).json({ error: 'Invalid or expired session' });
            return;
        }

        // Check if the user exists
        const userResult = await pool.query(
            'SELECT * FROM users WHERE email = $1',
            [decoded.email]
        );

        if (userResult.rows.length === 0) {
            res.status(401).json({ error: 'User not found' });
            return;
        }

        req.user = { email: decoded.email };
        next();
    } catch (error) {
        console.error('Token verification error:', error);
        res.status(403).json({ error: 'Invalid token' });
    }
};
