require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static('vial-segura-app/www'));

const JWT_SECRET = process.env.JWT_SECRET || 'viasegura_secret_2024';
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'admin123';
const REPORT_EXPIRY_HOURS = process.env.REPORT_EXPIRY_HOURS || 24;

const pool = new Pool({
  connectionString: process.env.database_url,
  ssl: { rejectUnauthorized: false }
});

async function initDB() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS reports (
        id SERIAL PRIMARY KEY,
        title VARCHAR(255),
        sub VARCHAR(255),
        time VARCHAR(255),
        icon VARCHAR(100),
        color VARCHAR(20),
        bg VARCHAR(20),
        lat DOUBLE PRECISION,
        lng DOUBLE PRECISION,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    console.log("Tabla de reportes verificada/creada.");
  } catch (err) {
    console.error("Error inicializando DB:", err);
  }
}
initDB();

// Limpiar reportes viejos cada hora
setInterval(async () => {
  try {
    const result = await pool.query(
      `DELETE FROM reports WHERE created_at < NOW() - INTERVAL '${REPORT_EXPIRY_HOURS} hours'`
    );
    console.log(`Reportes expirados eliminados: ${result.rowCount}`);
  } catch (err) {
    console.error("Error limpiando reportes:", err);
  }
}, 60 * 60 * 1000);

// Middleware JWT
function verifyToken(req, res, next) {
  const auth = req.headers['authorization'];
  if (!auth) return res.status(401).json({ error: 'Token requerido' });
  const token = auth.split(' ')[1];
  try {
    req.admin = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(403).json({ error: 'Token inválido o expirado' });
  }
}

// Rutas públicas
app.get('/', (req, res) => {
  res.send('API de Vía Segura en línea y funcionando correctamente.');
});

app.get('/api/reports', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM reports ORDER BY created_at DESC');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

app.post('/api/reports', async (req, res) => {
  try {
    const { title, sub, time, icon, color, bg, lat, lng } = req.body;
    const result = await pool.query(
      'INSERT INTO reports(title, sub, time, icon, color, bg, lat, lng) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *',
      [title, sub, time, icon, color, bg, lat, lng]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// Login admin
app.post('/api/admin/login', (req, res) => {
  const { username, password } = req.body;
  if (username === ADMIN_USER && password === ADMIN_PASS) {
    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '8h' });
    res.json({ token });
  } else {
    res.status(401).json({ error: 'Credenciales incorrectas' });
  }
});

// Rutas admin protegidas
app.get('/api/admin/reports', verifyToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM reports ORDER BY created_at DESC');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

app.delete('/api/admin/reports/:id', verifyToken, async (req, res) => {
  try {
    await pool.query('DELETE FROM reports WHERE id = $1', [req.params.id]);
    res.json({ message: 'Reporte eliminado' });
  } catch (err) {
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

app.delete('/api/admin/reports', verifyToken, async (req, res) => {
  try {
    await pool.query('DELETE FROM reports');
    res.json({ message: 'Todos los reportes eliminados' });
  } catch (err) {
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

const PORT = process.env.PORT || 3000;
if (process.env.NODE_ENV !== 'production') {
  app.listen(PORT, () => {
    console.log(`API de Vía Segura ejecutándose en http://localhost:${PORT}`);
  });
}

module.exports = app;
