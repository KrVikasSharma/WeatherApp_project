import db from '../db/index.js';

export async function findUserByEmail(email) {
  const res = await db.query('SELECT * FROM users WHERE email = $1', [email]);
  return res.rows[0];
}

export async function createUser({ name, email, hashedPassword }) {
  const res = await db.query(
    `INSERT INTO users (name, email, password) VALUES ($1, $2, $3)
     RETURNING id, name, email, created_at`,
    [name, email, hashedPassword]
  );
  return res.rows[0];
}

export async function getUserById(id) {
  const res = await db.query(
    'SELECT id, name, email, created_at FROM users WHERE id = $1',
    [id]
  );
  return res.rows[0];
}
