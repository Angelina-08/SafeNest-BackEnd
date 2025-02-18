import { Pool } from 'pg';
import dotenv from 'dotenv';

dotenv.config();

// Use the pooled connection URL for better performance
export const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false // Required for Neon database connection
    }
});
