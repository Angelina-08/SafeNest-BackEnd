import express from 'express';
import { 
  createNotification, 
  getNotifications, 
  updateNotificationStatus,
  getNotificationById
} from '../controllers/notificationController';
import { authenticateToken } from '../middleware/auth';
import multer from 'multer';

const router = express.Router();
const upload = multer({ storage: multer.memoryStorage() });

// Public route for receiving alerts from the detection script
router.post('/', upload.single('image'), createNotification);

// Protected routes that require authentication
router.get('/', authenticateToken, getNotifications);
router.get('/:eventId', authenticateToken, getNotificationById);
router.put('/:eventId/status', authenticateToken, updateNotificationStatus);

export default router;
