import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import authRoutes from './routes/auth.js';
import db from './db/index.js';
import path from 'path';
import fs from 'fs';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 4000;

app.use(cors());
app.use(express.json());

// Basic root
app.get('/', (req, res) => {
  res.json({ message: 'Weather backend up' });
});

// Auth routes mounted at /auth
app.use('/auth', authRoutes);

// health check
app.get('/health', async (req, res) => {
  try {
    await db.query('SELECT 1');
    res.json({ db: 'ok' });
  } catch (err) {
    res.status(500).json({ db: 'error', error: String(err) });
  }
});

app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
