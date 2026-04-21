const express = require('express');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3001;

app.use(cors());

app.get('/api/events', (_req, res) => {
  res.json({ events: [] });
});

app.listen(PORT, () => {
  console.log(`Minimal backend listening on http://localhost:${PORT}`);
});
