const express = require('express');
const path = require('path');

const app = express();

app.use(express.json());

// Serve static files from /public
app.use(express.static(path.join(__dirname, '../public')));

// Homepage
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

// The one and only correct flag for this challenge.
const CORRECT_FLAG = 'inroomctf{d3x_h3ad3r_f1x3d_4nd_4pk_d3c0mp1l3d}';

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
  res.json({ status: 'ok', challenge: 'Broken APK' });
});

app.post('/api/verify', (req, res) => {
  const submitted =
    req.body && typeof req.body.flag === 'string'
      ? req.body.flag.trim()
      : '';

  if (!submitted) {
    return res.status(400).json({
      status: 'error',
      correct: false,
      message: 'No flag submitted.'
    });
  }

  if (safeEqual(submitted, CORRECT_FLAG)) {
    return res.json({
      status: 'success',
      correct: true,
      message: 'DEX header repaired. APK decompiled. Flag verified.'
    });
  }

  res.json({
    status: 'failure',
    correct: false,
    message: 'Incorrect flag.'
  });
});

if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => console.log(`Server running on ${PORT}`));
}

module.exports = app;
