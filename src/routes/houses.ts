import { Router, Response } from 'express';
import { pool } from '../config/database';
import { authenticateToken, AuthRequest } from '../middleware/auth';

const router = Router();

// Get all houses for a user (including ones they have permission for)
router.get('/', authenticateToken, async (req: AuthRequest, res: Response) => {
  const userEmail = req.user?.email;

  if (!userEmail) {
    res.status(401).json({ error: 'User not authenticated' });
    return;
  }

  try {
    // Get houses owned by user and houses they have permission for
    const result = await pool.query(`
      SELECT DISTINCT
        h.home_id,
        h.home_name,
        h.home_image,
        h.home_owner,
        h.created_at,
        h.updated_at,
        u.email as owner_email,
        CASE 
          WHEN h.home_owner = $1 THEN 
            (
              SELECT json_agg(json_build_object(
                'email', p.user_id
              ))
              FROM permissions p
              WHERE p.home_id = h.home_id
            )
          ELSE NULL
        END as permissions
      FROM houses h
      LEFT JOIN users u ON h.home_owner = u.email
      LEFT JOIN permissions p ON h.home_id = p.home_id
      WHERE h.home_owner = $1 OR p.user_id = $1
    `, [userEmail]);

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching houses:', error);
    res.status(500).json({ error: 'Failed to fetch houses' });
  }
});

// Update house permissions
router.put('/:id/permissions', authenticateToken, async (req: AuthRequest, res: Response) => {
  const { id } = req.params;
  const { permissions } = req.body;
  const userEmail = req.user?.email;

  if (!userEmail) {
    res.status(401).json({ error: 'User not authenticated' });
    return;
  }

  try {
    // Verify user is the owner
    const house = await pool.query(
      'SELECT home_owner FROM houses WHERE home_id = $1',
      [id]
    );

    if (house.rows.length === 0) {
      res.status(404).json({ error: 'House not found' });
      return;
    }

    if (house.rows[0].home_owner !== userEmail) {
      res.status(403).json({ error: 'Only the owner can modify permissions' });
      return;
    }

    // Start transaction
    await pool.query('BEGIN');

    // Delete existing permissions
    await pool.query(
      'DELETE FROM permissions WHERE home_id = $1',
      [id]
    );

    // Add new permissions
    if (permissions && permissions.length > 0) {
      const values = permissions.map((email: string) => 
        `(${id}, '${email}')`
      ).join(',');

      await pool.query(`
        INSERT INTO permissions (home_id, user_id)
        VALUES ${values}
        ON CONFLICT (home_id, user_id) DO NOTHING
      `);
    }

    await pool.query('COMMIT');

    // Get updated permissions
    const result = await pool.query(`
      SELECT user_id as email
      FROM permissions
      WHERE home_id = $1
    `, [id]);

    res.json(result.rows);
  } catch (error) {
    await pool.query('ROLLBACK');
    console.error('Error updating permissions:', error);
    res.status(500).json({ error: 'Failed to update permissions' });
  }
});

// Update house details
router.put('/:id', authenticateToken, async (req: AuthRequest, res: Response) => {
  const { id } = req.params;
  const { name, imageUrl } = req.body;
  const userEmail = req.user?.email;

  if (!userEmail) {
    res.status(401).json({ error: 'User not authenticated' });
    return;
  }

  try {
    // Verify user is the owner
    const house = await pool.query(
      'SELECT home_owner FROM houses WHERE home_id = $1',
      [id]
    );

    if (house.rows.length === 0) {
      res.status(404).json({ error: 'House not found' });
      return;
    }

    if (house.rows[0].home_owner !== userEmail) {
      res.status(403).json({ error: 'Only the owner can modify the house' });
      return;
    }

    const result = await pool.query(
      'UPDATE houses SET home_name = $1, home_image = $2, updated_at = CURRENT_TIMESTAMP WHERE home_id = $3 RETURNING *',
      [name, imageUrl, id]
    );

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error updating house:', error);
    res.status(500).json({ error: 'Failed to update house' });
  }
});

// Create new house
router.post('/', authenticateToken, async (req: AuthRequest, res: Response) => {
  const { name, imageUrl } = req.body;
  const userEmail = req.user?.email;

  if (!userEmail) {
    res.status(401).json({ error: 'User not authenticated' });
    return;
  }

  try {
    const result = await pool.query(
      'INSERT INTO houses (home_name, home_image, home_owner) VALUES ($1, $2, $3) RETURNING *',
      [name, imageUrl, userEmail]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error creating house:', error);
    res.status(500).json({ error: 'Failed to create house' });
  }
});

export default router;
