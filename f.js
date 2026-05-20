require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');

const rateLimit = require('express-rate-limit');

const multer = require('multer');
const cloudinary = require('cloudinary').v2;

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB máximo
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) cb(null, true);
    else cb(new Error('Solo se permiten imágenes'), false);
  }
});

const adminLoginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 10,
  message: { error: 'Demasiados intentos. Espera 15 minutos.' }
});

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
  const { title, sub, time, icon, color, bg, lat, lng, user_email, foto_url, descripcion } = req.body;
  if (!user_email) return res.status(401).json({ error: 'Debes iniciar sesión para reportar' });
  try {
    const result = await pool.query(
      'INSERT INTO reports(title, sub, time, icon, color, bg, lat, lng, user_email, foto_url, descripcion) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING *',
      [title, sub, time, icon, color, bg, lat, lng, user_email || null, foto_url || null, descripcion || null]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

app.post('/api/upload', upload.single('foto'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No se recibió imagen' });
    const b64 = Buffer.from(req.file.buffer).toString('base64');
    const dataURI = `data:${req.file.mimetype};base64,${b64}`;
    const result = await cloudinary.uploader.upload(dataURI, {
      folder: 'via-segura',
      transformation: [{ width: 800, quality: 'auto', fetch_format: 'auto' }]
    });
    res.json({ url: result.secure_url });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error subiendo imagen' });
  }
});

// Login admin
app.post('/api/admin/login', adminLoginLimiter, (req, res) => {
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

app.get('/api/cleanup', async (req, res) => {
  const secret = req.headers['x-cleanup-secret'];
  if (secret !== process.env.CLEANUP_SECRET) {
    return res.status(401).json({ error: 'No autorizado' });
  }
  try {
    const result = await pool.query(
      "DELETE FROM reports WHERE created_at < NOW() - INTERVAL '72 hours'"
    );
    res.json({ deleted: result.rowCount });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Registro con email
app.post('/api/auth/register', async (req, res) => {
  const { email, password, name } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email y contraseña requeridos' });
  try {
    const exists = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (exists.rows.length > 0) return res.status(409).json({ error: 'Este correo ya está registrado' });
    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users(email, password_hash, name, provider) VALUES($1,$2,$3,$4) RETURNING id, email, name',
      [email, hash, name || email.split('@')[0], 'email']
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Error interno' });
  }
});

// Login con email
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email y contraseña requeridos' });
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1 AND provider = $2', [email, 'email']);
    if (result.rows.length === 0) return res.status(401).json({ error: 'Correo o contraseña incorrectos' });
    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Correo o contraseña incorrectos' });
    res.json({ id: user.id, email: user.email, name: user.name, role: user.role });
  } catch (err) {
    res.status(500).json({ error: 'Error interno' });
  }
});

// Login/registro con Google
app.post('/api/auth/google', async (req, res) => {
  const { email, name } = req.body;
  if (!email) return res.status(400).json({ error: 'Email requerido' });
  try {
    let result = await pool.query('SELECT id, email, name, role FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      result = await pool.query(
      'INSERT INTO users(email, name, provider) VALUES($1,$2,$3) RETURNING id, email, name, role',
      [email, name, 'google']
    );
  }
  res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Error interno' });
  }
});

module.exports = app;
