const express = require('express');

const app = express();
app.use(express.json());

// The one and only correct flag for this challenge.
const CORRECT_FLAG = 'inroomctf{d3x_h3ad3r_f1x3d_4nd_4pk_d3c0mp1l3d}';

// Simple constant-time-ish comparison to avoid trivial timing side channels.
function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;
  let mismatch = 0;
  for (let i = 0; i < a.length; i++) {
    mismatch |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return mismatch === 0;
}

app.get('/api/health', (req, res) => {
  res.status(200).json({ status: 'ok', challenge: 'Broken APK' });
});

app.post('/api/verify', (req, res) => {
  const submitted = req.body && typeof req.body.flag === 'string'
    ? req.body.flag.trim()
    : '';

  if (!submitted) {
    return res.status(400).json({
      status: 'error',
      correct: false,
      message: 'No flag submitted. POST { "flag": "inroomctf{...}" }',
    });
  }

  const isCorrect = safeEqual(submitted, CORRECT_FLAG);

  if (isCorrect) {
    return res.status(200).json({
      status: 'success',
      correct: true,
      message: 'DEX header repaired. APK decompiled. Flag verified. Diagnostic complete.',
    });
  }

  return res.status(200).json({
    status: 'failure',
    correct: false,
    message: 'Incorrect flag. Re-check the DEX header repair and both decompiled flag fragments.',
  });
});

// Catch-all for unknown API routes
app.use('/api', (req, res) => {
  res.status(404).json({ status: 'error', message: 'Unknown API route' });
});

// Local dev entrypoint (Vercel imports `app` directly as the handler)
if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => console.log(`Broken APK CTF server listening on :${PORT}`));
}

module.exports = app;
