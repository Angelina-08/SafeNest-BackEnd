import express, { Response } from 'express';
import { Pool } from 'pg';
import { authenticateToken, AuthRequest } from '../middleware/auth';

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
      'SELECT * FROM houses WHERE user_email = $1',
      [userEmail]
    );

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching houses:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Create a new house for the authenticated user
router.post('/', authenticateToken, async (req: AuthRequest, res: Response) => {
  try {
    const userEmail = req.user?.email;
    if (!userEmail) {
      res.status(401).json({ error: 'User not authenticated' });
      return;
    }

    const { homeName, homeImage } = req.body;
    
    if (!homeName || !homeImage) {
      res.status(400).json({ error: 'Home name and image are required' });
      return;
    }

    const result = await pool.query(
      'INSERT INTO houses (home_name, home_image, user_email) VALUES ($1, $2, $3) RETURNING *',
      [homeName, homeImage, userEmail]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error creating house:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

export default router;
