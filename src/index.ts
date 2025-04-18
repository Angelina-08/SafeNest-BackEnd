import express from 'express';
import dotenv from 'dotenv';
import cors from 'cors';
import authRoutes from './routes/auth';
import housesRoutes from './routes/houses';
import cameraRoutes from './routes/camera';
import notificationRoutes from './routes/notification';
import fileUpload from 'express-fileupload';

dotenv.config();

const app = express();

// CORS configuration
app.use(cors({
    origin: [
        'http://localhost:3001',           // Keep local development
        'http://localhost:3000',           // Keep local development
        'https://safenest-frontend.vercel.app'  // Add your deployed frontend URL
      ],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

// Middleware
app.use(express.json({ limit: '50mb' })); // Increase payload size limit for JSON requests
app.use(fileUpload()); // Add file upload middleware for handling image uploads

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/houses', housesRoutes);
app.use('/api/camera', cameraRoutes);
app.use('/api/notifications', notificationRoutes);

// Default and Health check endpoint
app.get('/', (req, res) => {
    res.status(200).json({ status: 'ok' });
});

// For local development
if (process.env.NODE_ENV !== 'production') {
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => {
        console.log(`Server is running on port ${PORT}`);
    });
}

// For Vercel
export default app;
