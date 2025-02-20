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
        const decoded = jwt.verify(token, process.env.JWT_SECRET as string) as { email: string };
        
        const session = await pool.query(
            'SELECT * FROM session_information WHERE jwt_token = $1 AND is_active = true AND session_expiry > $2',
            [token, Math.floor(Date.now() / 1000)]
        );

        if (session.rows.length === 0) {
            res.status(401).json({ error: 'Invalid or expired session' });
            return;
        }

        req.user = { email: decoded.email };
        next();
    } catch (error) {
        res.status(403).json({ error: 'Invalid token' });
        return;
    }
};
