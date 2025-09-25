import db from '../db/index.js';

// Save a location for a user
export async function saveLocation(userId, location) {
  const res = await db.query(
    `INSERT INTO locations (user_id, name, country, lat, lon, timestamp)
     VALUES ($1, $2, $3, $4, $5, NOW())
     RETURNING id, name, country, lat, lon, timestamp`,
    [userId, location.name, location.country, location.lat, location.lon]
  );
  return res.rows[0];
}

// Fetch all user's locations
export async function getUserLocations(userId) {
  const res = await db.query(
    'SELECT id, name, country, lat, lon, timestamp FROM locations WHERE user_id = $1 ORDER BY timestamp DESC',
    [userId]
  );
  return res.rows;
}

// Remove a location for a user
export async function removeLocation(userId, locationId) {
  await db.query(
    'DELETE FROM locations WHERE user_id = $1 AND id = $2',
    [userId, locationId]
  );
}
