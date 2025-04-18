import { Pool } from 'pg';
import dotenv from 'dotenv';

dotenv.config();

// Create a new database pool with the connection string from environment variables
export const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Test the connection
pool.on('connect', () => {
  console.log('Connected to the database');
});

pool.on('error', (err) => {
  console.error('Unexpected error on idle client', err);
  process.exit(-1);
});

// Export a function to query the database
export const query = (text: string, params: any[]) => pool.query(text, params);
