/**
 * PixelTruth v3.0 – Backend Server
 * server.js  |  Node.js + Express
 *
 * Handles uploads and forensic analysis for:
 *   - Images  (Sharp pixel analysis)
 *   - Video   (frame extraction + analysis)
 *   - Audio   (spectral analysis)
 *   - Text    (linguistic pattern analysis)
 */

'use strict';

const express = require('express');
const multer = require('multer');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const imageAnalyzer = require('./analyzers/imageAnalyzer');
const videoAnalyzer = require('./analyzers/videoAnalyzer');
const audioAnalyzer = require('./analyzers/audioAnalyzer');
const textAnalyzer = require('./analyzers/textAnalyzer');

const app = express();
const PORT = process.env.PORT || 3001;

/* ── Middleware ─────────────────────────────────────────── */
app.use(cors());
app.use(express.json({ limit: '5mb' }));

/* SERVE FRONTEND */
const FRONTEND_PATH = path.join(__dirname, '../FRONTEND');
app.use(express.static(FRONTEND_PATH));

app.get('/', (req, res) => {
  res.sendFile(path.join(FRONTEND_PATH, 'index.html'));
});

/* ── Upload config ─────────────────────────────────────── */
const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    const name = `upload_${Date.now()}_${Math.random().toString(36).slice(2, 8)}${ext}`;
    cb(null, name);
  },
});

const ALLOWED_TYPES = new Set([
  // Images
  'image/jpeg', 'image/png', 'image/webp', 'image/bmp',
  // Video
  'video/mp4', 'video/webm', 'video/quicktime', 'video/x-msvideo',
  // Audio
  'audio/mpeg', 'audio/wav', 'audio/ogg', 'audio/flac',
  'audio/x-wav', 'audio/mp3', 'audio/wave',
]);

const upload = multer({
  storage,
  limits: { fileSize: 50 * 1024 * 1024 }, // 50 MB
  fileFilter: (req, file, cb) => {
    if (ALLOWED_TYPES.has(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Unsupported file type: ' + file.mimetype));
    }
  },
});

/* ── Health check ───────────────────────────────────────── */
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    version: '3.0',
    engine: 'PixelTruth Forensic API',
    capabilities: ['image', 'video', 'audio', 'text'],
  });
});

/* ── Detect content type from MIME ──────────────────────── */
function getContentType(mimeType) {
  if (mimeType.startsWith('image/')) return 'image';
  if (mimeType.startsWith('video/')) return 'video';
  if (mimeType.startsWith('audio/')) return 'audio';
  return 'unknown';
}

/* ── Image Analysis Endpoint ────────────────────────────── */
app.post('/api/analyze', upload.single('file'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file provided.' });
  }

  const filePath = req.file.path;
  const contentType = getContentType(req.file.mimetype);

  try {
    console.log(`[${new Date().toISOString()}] Analyzing ${contentType}: ${req.file.originalname} (${req.file.size} bytes)`);

    let result;
    const meta = {
      originalName: req.file.originalname,
      mimeType: req.file.mimetype,
      size: req.file.size,
    };

    switch (contentType) {
      case 'image':
        result = await imageAnalyzer.analyze(filePath, meta);
        break;
      case 'video':
        result = await videoAnalyzer.analyze(filePath, meta);
        break;
      case 'audio':
        result = await audioAnalyzer.analyze(filePath, meta);
        break;
      default:
        throw new Error('Unsupported content type: ' + contentType);
    }

    res.json({ success: true, contentType, result });
  } catch (err) {
    console.error('Analysis error:', err.message);
    res.status(500).json({ error: 'Analysis failed: ' + err.message });
  } finally {
    // Clean up uploaded file
    fs.unlink(filePath, () => {});
  }
});

/* ── Text Analysis Endpoint (JSON body, no file) ────────── */
app.post('/api/analyze-text', async (req, res) => {
  const { text } = req.body;
  if (!text || typeof text !== 'string' || text.trim().length < 20) {
    return res.status(400).json({ error: 'Please provide at least 20 characters of text to analyze.' });
  }

  try {
    console.log(`[${new Date().toISOString()}] Analyzing text: ${text.length} characters`);
    const result = textAnalyzer.analyze(text.trim());
    res.json({ success: true, contentType: 'text', result });
  } catch (err) {
    console.error('Text analysis error:', err.message);
    res.status(500).json({ error: 'Text analysis failed: ' + err.message });
  }
});

/* ── Error handler ──────────────────────────────────────── */
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE')
      return res.status(413).json({ error: 'File too large (max 50MB).' });
    return res.status(400).json({ error: err.message });
  }
  if (err.message && err.message.includes('Unsupported file type')) {
    return res.status(400).json({ error: err.message });
  }
  console.error(err);
  res.status(500).json({ error: 'Internal server error.' });
});

/* ── Serve index.html for all non-API routes ────────────── */
app.get('/{*splat}', (req, res) => {
  res.sendFile(path.join(FRONTEND_PATH, 'index.html'));
});

/* ── Start ──────────────────────────────────────────────── */
app.listen(PORT, () => {
  console.log(`\n  🔬 PixelTruth v3.0 – AI Content Forensic Analyzer`);
  console.log(`  ✅ Server running at   http://localhost:${PORT}`);
  console.log(`  📡 File analysis:      POST /api/analyze`);
  console.log(`  📝 Text analysis:      POST /api/analyze-text`);
  console.log(`  🩺 Health check:       GET  /api/health`);
  console.log(`  📦 Media types:        Image, Video, Audio, Text\n`);
});
