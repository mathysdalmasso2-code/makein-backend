require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const nodemailer = require('nodemailer');
const crypto = require('crypto');

const app = express();
app.use(express.json());
app.use(cors());

// ============ CONNEXION MONGODB ============
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('✅ MongoDB connecté'))
  .catch(err => console.error('❌ Erreur MongoDB:', err));

// ============ MODELE UTILISATEUR ============
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email:    { type: String, required: true, unique: true },
  password: { type: String, required: true },
  verified: { type: Boolean, default: false },
  verifyToken: { type: String },
  role: { type: String, default: 'user' }, // user / admin / superadmin
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);

// ============ NODEMAILER ============
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// ============ MIDDLEWARE AUTH ============
function authMiddleware(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token manquant' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Token invalide' });
  }
}

// ============ ROUTES ============

// Inscription
app.post('/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!username || !email || !password)
      return res.status(400).json({ error: 'Champs manquants' });

    const exists = await User.findOne({ $or: [{ email }, { username }] });
    if (exists) return res.status(400).json({ error: 'Pseudo ou email déjà utilisé' });

    const hashed = await bcrypt.hash(password, 10);
    const verifyToken = crypto.randomBytes(32).toString('hex');

    const user = new User({ username, email, password: hashed, verifyToken });
    await user.save();

    // Envoyer mail de vérification
    const verifyUrl = `${process.env.BASE_URL || 'http://localhost:3000'}/verify/${verifyToken}`;
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: '✅ Makein - Vérification de ton compte',
      html: `
        <div style="font-family:sans-serif;background:#0f1020;color:#fff;padding:30px;border-radius:10px">
          <h2 style="color:#a78bfa">Makein Launcher</h2>
          <p>Salut <b>${username}</b> ! Clique sur le bouton ci-dessous pour vérifier ton compte.</p>
          <a href="${verifyUrl}" style="display:inline-block;margin-top:16px;background:#7c5af6;color:#fff;padding:12px 24px;border-radius:7px;text-decoration:none;font-weight:600">Vérifier mon compte</a>
          <p style="margin-top:16px;color:rgba(255,255,255,0.4);font-size:12px">Si tu n'as pas créé de compte, ignore ce mail.</p>
        </div>
      `
    });

    res.json({ ok: true, message: 'Compte créé ! Vérifie ton email.' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Vérification email
app.get('/verify/:token', async (req, res) => {
  try {
    const user = await User.findOne({ verifyToken: req.params.token });
    if (!user) return res.status(400).send('Token invalide ou expiré.');
    user.verified = true;
    user.verifyToken = null;
    await user.save();
    res.send(`
      <div style="font-family:sans-serif;background:#0f1020;color:#fff;padding:30px;text-align:center">
        <h2 style="color:#a78bfa">✅ Compte vérifié !</h2>
        <p>Tu peux maintenant te connecter sur le Makein Launcher.</p>
      </div>
    `);
  } catch (e) {
    res.status(500).send('Erreur serveur');
  }
});

// Connexion
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user) return res.status(400).json({ error: 'Pseudo ou mot de passe incorrect' });
    if (!user.verified) return res.status(400).json({ error: 'Vérifie ton email avant de te connecter' });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).json({ error: 'Pseudo ou mot de passe incorrect' });

    const token = jwt.sign(
      { id: user._id, username: user.username, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({ ok: true, token, username: user.username, role: user.role });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Profil (route protégée)
app.get('/me', authMiddleware, async (req, res) => {
  const user = await User.findById(req.user.id).select('-password -verifyToken');
  res.json(user);
});

// Liste des joueurs (admin)
app.get('/admin/users', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin' && req.user.role !== 'superadmin')
    return res.status(403).json({ error: 'Accès refusé' });
  const users = await User.find().select('-password -verifyToken');
  res.json(users);
});

// ============ LANCEMENT ============
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Serveur Makein lancé sur le port ${PORT}`));