import express, { Response } from 'express';
import { Pool } from 'pg';
import { authenticateToken } from '../src/middleware/auth';

interface AuthRequest extends express.Request {
  user?: {
    email: string;
  };
}

const router = express.Router();
const pool = new Pool();

// Get all houses for the authenticated user
router.get('/', authenticateToken, async (req: AuthRequest, res: Response) => {
  try {
    const userEmail = req.user?.email;
    if (!userEmail) {
      res.status(401).json({ error: 'User not authenticated' });
      return;
    }

    const result = await pool.query(
      'SELECT * FROM houses WHERE home_owner = $1 ORDER BY created_at DESC',
      [userEmail]
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching houses:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Create a new house
router.post('/', authenticateToken, async (req: AuthRequest, res: Response) => {
  try {
    const { homeName, homeImage } = req.body;
    const userEmail = req.user?.email;
    
    if (!userEmail) {
      res.status(401).json({ error: 'User not authenticated' });
      return;
    }

    const result = await pool.query(
      'INSERT INTO houses (home_name, home_owner, home_image) VALUES ($1, $2, $3) RETURNING *',
      [homeName, userEmail, homeImage]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error creating house:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

export default router;
