import express from 'express';
import dotenv from 'dotenv';
import cors from 'cors';
import authRoutes from './routes/auth';
import housesRoutes from './routes/houses';

dotenv.config();

const app = express();

// CORS configuration
app.use(cors({
    origin: [
        'http://localhost:3001',           // Keep local development
        'https://safenest-frontend.vercel.app'  // Add your deployed frontend URL
      ],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

// Middleware
app.use(express.json());

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/houses', housesRoutes);

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
