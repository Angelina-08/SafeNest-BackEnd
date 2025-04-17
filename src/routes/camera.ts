import { Router, Response } from 'express';
import { pool } from '../config/database';
import { authenticateToken, AuthRequest } from '../middleware/auth';

const router = Router();

// Get all cameras for a specific house
router.get('/house/:homeId', authenticateToken, async (req: AuthRequest, res: Response) => {
  const { homeId } = req.params;
  const userEmail = req.user?.email;

  if (!userEmail) {
    res.status(401).json({ error: 'User not authenticated' });
    return;
  }

  try {
    // Check if user owns the house or has permission
    const accessCheck = await pool.query(`
      SELECT 1 
      FROM houses h
      LEFT JOIN permissions p ON h.home_id = p.home_id AND p.user_id = $1
      WHERE h.home_id = $2 AND (h.home_owner = $1 OR p.user_id IS NOT NULL)
    `, [userEmail, homeId]);

    if (accessCheck.rows.length === 0) {
      res.status(403).json({ error: 'Access denied to this house' });
      return;
    }

    // Get all cameras for the house
    const result = await pool.query(`
      SELECT 
        camera_id, 
        camera_name, 
        camera_address, 
        home_id, 
        created_at, 
        updated_at
      FROM cameras
      WHERE home_id = $1
      ORDER BY camera_name
    `, [homeId]);

    // Transform the response to match frontend interface
    const cameras = result.rows.map(camera => ({
      cameraId: camera.camera_id,
      cameraName: camera.camera_name,
      cameraAddress: camera.camera_address,
      homeId: camera.home_id,
      createdAt: camera.created_at,
      updatedAt: camera.updated_at
    }));

    res.json(cameras);
  } catch (error) {
    console.error('Error fetching cameras:', error);
    res.status(500).json({ error: 'Failed to fetch cameras' });
  }
});

// Get a specific camera by ID
router.get('/:id', authenticateToken, async (req: AuthRequest, res: Response) => {
  const { id } = req.params;
  const userEmail = req.user?.email;

  if (!userEmail) {
    res.status(401).json({ error: 'User not authenticated' });
    return;
  }

  try {
    // Check if user has access to the camera
    const result = await pool.query(`
      SELECT c.*
      FROM cameras c
      JOIN houses h ON c.home_id = h.home_id
      LEFT JOIN permissions p ON h.home_id = p.home_id AND p.user_id = $1
      WHERE c.camera_id = $2 AND (h.home_owner = $1 OR p.user_id IS NOT NULL)
    `, [userEmail, id]);

    if (result.rows.length === 0) {
      res.status(404).json({ error: 'Camera not found or access denied' });
      return;
    }

    const camera = result.rows[0];
    res.json({
      cameraId: camera.camera_id,
      cameraName: camera.camera_name,
      cameraAddress: camera.camera_address,
      homeId: camera.home_id,
      createdAt: camera.created_at,
      updatedAt: camera.updated_at
    });
  } catch (error) {
    console.error('Error fetching camera:', error);
    res.status(500).json({ error: 'Failed to fetch camera' });
  }
});

// Create a new camera
router.post('/', authenticateToken, async (req: AuthRequest, res: Response) => {
  const { cameraName, cameraAddress, homeId } = req.body;
  const userEmail = req.user?.email;

  if (!userEmail) {
    res.status(401).json({ error: 'User not authenticated' });
    return;
  }

  // Validate required fields
  if (!cameraName || !cameraAddress || !homeId) {
    res.status(400).json({ error: 'Camera name, address, and home ID are required' });
    return;
  }

  try {
    // Verify user is the owner of the house or has permission
    const house = await pool.query(`
      SELECT h.home_owner
      FROM houses h
      LEFT JOIN permissions p ON h.home_id = p.home_id AND p.user_id = $1
      WHERE h.home_id = $2 AND (h.home_owner = $1 OR p.user_id IS NOT NULL)
    `, [userEmail, homeId]);

    if (house.rows.length === 0) {
      res.status(403).json({ error: 'You do not have access to this house' });
      return;
    }

    // Create the camera
    const result = await pool.query(
      'INSERT INTO cameras (camera_name, camera_address, home_id) VALUES ($1, $2, $3) RETURNING *',
      [cameraName, cameraAddress, homeId]
    );

    res.status(201).json({
      cameraId: result.rows[0].camera_id,
      cameraName: result.rows[0].camera_name,
      cameraAddress: result.rows[0].camera_address,
      homeId: result.rows[0].home_id,
      createdAt: result.rows[0].created_at,
      updatedAt: result.rows[0].updated_at
    });
  } catch (error) {
    console.error('Error creating camera:', error);
    res.status(500).json({ error: 'Failed to create camera' });
  }
});

// Update a camera
router.put('/:id', authenticateToken, async (req: AuthRequest, res: Response) => {
  const { id } = req.params;
  const { cameraName, cameraAddress } = req.body;
  const userEmail = req.user?.email;

  if (!userEmail) {
    res.status(401).json({ error: 'User not authenticated' });
    return;
  }

  // Validate required fields
  if (!cameraName && !cameraAddress) {
    res.status(400).json({ error: 'Camera name or address must be provided' });
    return;
  }

  try {
    // Verify user has access to the camera
    const camera = await pool.query(`
      SELECT c.*, h.home_owner
      FROM cameras c
      JOIN houses h ON c.home_id = h.home_id
      LEFT JOIN permissions p ON h.home_id = p.home_id AND p.user_id = $1
      WHERE c.camera_id = $2 AND (h.home_owner = $1 OR p.user_id IS NOT NULL)
    `, [userEmail, id]);

    if (camera.rows.length === 0) {
      res.status(404).json({ error: 'Camera not found or access denied' });
      return;
    }

    // Build the update query dynamically based on provided fields
    let updateQuery = 'UPDATE cameras SET updated_at = CURRENT_TIMESTAMP';
    const queryParams = [];
    let paramIndex = 1;

    if (cameraName) {
      updateQuery += `, camera_name = $${paramIndex}`;
      queryParams.push(cameraName);
      paramIndex++;
    }

    if (cameraAddress) {
      updateQuery += `, camera_address = $${paramIndex}`;
      queryParams.push(cameraAddress);
      paramIndex++;
    }

    updateQuery += ` WHERE camera_id = $${paramIndex} RETURNING *`;
    queryParams.push(id);

    // Execute the update
    const result = await pool.query(updateQuery, queryParams);

    res.json({
      cameraId: result.rows[0].camera_id,
      cameraName: result.rows[0].camera_name,
      cameraAddress: result.rows[0].camera_address,
      homeId: result.rows[0].home_id,
      createdAt: result.rows[0].created_at,
      updatedAt: result.rows[0].updated_at
    });
  } catch (error) {
    console.error('Error updating camera:', error);
    res.status(500).json({ error: 'Failed to update camera' });
  }
});

// Delete a camera
router.delete('/:id', authenticateToken, async (req: AuthRequest, res: Response) => {
  const { id } = req.params;
  const userEmail = req.user?.email;

  if (!userEmail) {
    res.status(401).json({ error: 'User not authenticated' });
    return;
  }

  try {
    // Verify user has access to the camera
    const camera = await pool.query(`
      SELECT c.*, h.home_owner
      FROM cameras c
      JOIN houses h ON c.home_id = h.home_id
      WHERE c.camera_id = $1 AND h.home_owner = $2
    `, [id, userEmail]);

    if (camera.rows.length === 0) {
      res.status(404).json({ error: 'Camera not found or you are not the owner' });
      return;
    }

    // Only house owners can delete cameras
    if (camera.rows[0].home_owner !== userEmail) {
      res.status(403).json({ error: 'Only the house owner can delete cameras' });
      return;
    }

    // Delete the camera
    await pool.query('DELETE FROM cameras WHERE camera_id = $1', [id]);

    res.json({ message: 'Camera deleted successfully' });
  } catch (error) {
    console.error('Error deleting camera:', error);
    res.status(500).json({ error: 'Failed to delete camera' });
  }
});

export default router;
