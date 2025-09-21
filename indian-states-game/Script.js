require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');

const app = express();
app.use(helmet());
app.use(express.json());
app.use(cors({
  origin: process.env.CLIENT_URL || '*'
}));

// basic rate limit
app.use(rateLimit({ windowMs: 1*60*1000, max: 100 }));

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser:true, useUnifiedTopology:true })
  .then(() => console.log('Mongo connected'))
  .catch(err => console.error('Mongo error', err));

// Models
const State = require('./models/State');
const Picture = require('./models/Picture');
const User = require('./models/User');
const Score = require('./models/Score');

// Serve uploaded images
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// --- Simple API ---
// GET /api/game -> { images: [...], states: [...] }
app.get('/api/game', async (req, res) => {
  const images = await Picture.find().lean();
  const states = await State.find().lean();
  res.json({ images, states });
});

// POST /api/score -> save score
app.post('/api/score', async (req, res) => {
  const { userId, score, timeTaken } = req.body;
  try {
    const s = await Score.create({ user: userId||null, score, timeTaken });
    res.json({ ok: true, score: s });
  } catch (e) {
    res.status(500).json({ ok:false, error: e.message });
  }
});

// Admin image upload (use multer)
const multer = require('multer');
const uploadsDir = path.join(__dirname, 'uploads');
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => {
    const unique = Date.now() + '-' + file.originalname.replace(/\s+/g,'-');
    cb(null, unique);
  }
});
const upload = multer({ storage });

app.post('/api/upload', upload.single('image'), async (req, res) => {
  const { stateId, name, alt } = req.body;
  if (!req.file) return res.status(400).json({ ok:false, error:'No file' });
  const pic = await Picture.create({
    name: name || req.file.originalname,
    filename: `/uploads/${req.file.filename}`,
    stateId,
    alt: alt || name || req.file.originalname
  });
  res.json({ ok:true, picture: pic });
});

// simple auth (register, login) - uses bcrypt & jwt
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

app.post('/api/auth/register', async (req,res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) return res.status(400).json({ error:'missing' });
  const existing = await User.findOne({ email });
  if (existing) return res.status(400).json({ error:'exists' });
  const hash = await bcrypt.hash(password, 10);
  const u = await User.create({ username, email, passwordHash: hash });
  res.json({ ok:true, user: { id: u._id, username: u.username }});
});

app.post('/api/auth/login', async (req,res) => {
  const { email, password } = req.body;
  const u = await User.findOne({ email });
  if (!u) return res.status(400).json({ error:'no user' });
  const valid = await bcrypt.compare(password, u.passwordHash);
  if (!valid) return res.status(400).json({ error:'invalid' });
  const token = jwt.sign({ id: u._id }, process.env.JWT_SECRET, { expiresIn:'7d' });
  res.json({ ok:true, token, user: { id: u._id, username: u.username }});
});

// Start
const port = process.env.PORT || 4000;
app.listen(port, () => console.log('Server running on', port));
