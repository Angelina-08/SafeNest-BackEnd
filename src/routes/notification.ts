import express from 'express';
import type { UploadedFile } from 'express-fileupload';
import { authenticateToken, AuthRequest } from '../middleware/auth';
import { pool } from '../db';
import { put } from '@vercel/blob';
import { sendEmail } from '../utils/mailer';

const router = express.Router();
// fileUpload middleware is applied globally in index.ts

// Public route for receiving alerts from the detection script
router.post('/', async (req: express.Request, res: express.Response) => {
  try {
    // Check if required data is present
    if (!req.body.image || !req.body.cameraId) {
      return res.status(400).json({ error: 'Missing required fields: image or cameraId' });
    }

    const cameraId = parseInt(req.body.cameraId);
    
    // Convert base64 image to buffer
    const imageBase64 = req.body.image;
    const imageBuffer = Buffer.from(imageBase64, 'base64');
    
    // Validate camera exists
    const cameraResult = await pool.query(
      'SELECT c.camera_id, c.camera_name, h.home_id, h.home_name, u.email, u.first_name FROM cameras c ' +
      'JOIN houses h ON c.home_id = h.home_id ' +
      'JOIN users u ON h.home_owner = u.email ' +
      'WHERE c.camera_id = $1',
      [cameraId]
    );

    if (cameraResult.rows.length === 0) {
      return res.status(404).json({ error: 'Camera not found' });
    }

    const camera = cameraResult.rows[0];
    
    // Upload image to Vercel Blob Storage
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const fileName = `alerts/${camera.home_id}/${cameraId}/${timestamp}.jpg`;
    
    // Upload to blob storage
    const { url } = await put(fileName, imageBuffer, { 
      access: 'public',
      contentType: 'image/jpeg'
    });

    // Insert notification into database
    const result = await pool.query(
      'INSERT INTO notifications (camera_id, status, blob_url) VALUES ($1, $2, $3) RETURNING *',
      [cameraId, 'unread', url]
    );

    const notification = result.rows[0];

    // Send email notification
    const emailSubject = 'SafeNest Alert: Potential Danger Detected';
    const emailBody = `
      <h1>⚠️ SafeNest Alert: Potential Danger Detected</h1>
      <p>Hello ${camera.first_name},</p>
      <p>Our system has detected a potential danger situation at your property:</p>
      <ul>
        <li><strong>Home:</strong> ${camera.home_name}</li>
        <li><strong>Camera:</strong> ${camera.camera_name}</li>
        <li><strong>Time:</strong> ${new Date().toLocaleString()}</li>
      </ul>
      <p>Please check your SafeNest dashboard immediately to review this alert.</p>
      <p>If this is an emergency, please contact emergency services.</p>
      <p>The SafeNest Team</p>
    `;

    await sendEmail(camera.email, emailSubject, emailBody);

    return res.status(201).json({
      message: 'Notification created successfully',
      notification
    });
  } catch (error) {
    console.error('Error creating notification:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// Get notifications for a user
router.get('/', authenticateToken, async (req: AuthRequest, res: express.Response) => {
  const userEmail = req.user?.email;
  
  if (!userEmail) {
    return res.status(401).json({ error: 'User not authenticated' });
  }

  try {
    // Get the latest 10 notifications for all houses owned by the user
    const result = await pool.query(
      'SELECT n.*, c.camera_name, h.home_name, h.home_id FROM notifications n ' +
      'JOIN cameras c ON n.camera_id = c.camera_id ' +
      'JOIN houses h ON c.home_id = h.home_id ' +
      'WHERE h.home_owner = $1 ' +
      'ORDER BY CASE WHEN n.status = \'unread\' THEN 0 ELSE 1 END, ' +
      'n.timestamp DESC ' +
      'LIMIT 10',
      [userEmail]
    );

    return res.status(200).json({
      notifications: result.rows
    });
  } catch (error) {
    console.error('Error fetching notifications:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// Get notification details by ID
router.get('/:eventId', authenticateToken, async (req: AuthRequest, res: express.Response) => {
  const { eventId } = req.params;
  const userEmail = req.user?.email;
  
  if (!userEmail) {
    return res.status(401).json({ error: 'User not authenticated' });
  }

  try {
    // Get notification details if it belongs to a house owned by the user
    const result = await pool.query(
      'SELECT n.*, c.camera_name, h.home_name, h.home_id FROM notifications n ' +
      'JOIN cameras c ON n.camera_id = c.camera_id ' +
      'JOIN houses h ON c.home_id = h.home_id ' +
      'WHERE n.event_id = $1 AND h.home_owner = $2',
      [eventId, userEmail]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Notification not found or not authorized' });
    }

    return res.status(200).json({
      notification: result.rows[0]
    });
  } catch (error) {
    console.error('Error fetching notification details:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// Update notification status (resolved or false_alarm)
router.put('/:eventId/status', authenticateToken, async (req: AuthRequest, res: express.Response) => {
  const { eventId } = req.params;
  const { status } = req.body;
  const userEmail = req.user?.email;
  
  if (!userEmail) {
    return res.status(401).json({ error: 'User not authenticated' });
  }

  try {
    if (!status || !['resolved', 'false_alarm'].includes(status)) {
      return res.status(400).json({ error: 'Invalid status. Must be "resolved" or "false_alarm"' });
    }

    // Verify the notification belongs to a house owned by the user
    const checkResult = await pool.query(
      'SELECT n.event_id FROM notifications n ' +
      'JOIN cameras c ON n.camera_id = c.camera_id ' +
      'JOIN houses h ON c.home_id = h.home_id ' +
      'WHERE n.event_id = $1 AND h.home_owner = $2',
      [eventId, userEmail]
    );

    if (checkResult.rows.length === 0) {
      return res.status(404).json({ error: 'Notification not found or not authorized' });
    }

    // Update the notification status
    const result = await pool.query(
      'UPDATE notifications SET status = $1 WHERE event_id = $2 RETURNING *',
      [status, eventId]
    );

    return res.status(200).json({
      message: 'Notification status updated successfully',
      notification: result.rows[0]
    });
  } catch (error) {
    console.error('Error updating notification status:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

export default router;
