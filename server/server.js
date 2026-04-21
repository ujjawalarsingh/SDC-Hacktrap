const express = require('express');
const cors = require('cors');
const { startEventGenerator } = require('./generator');

const app = express();
const PORT = process.env.PORT || 3001;
const events = [];

startEventGenerator(events);

app.use(cors());

app.get('/api/events', (_req, res) => {
  res.json({ events: events.slice(-50) });
});

app.listen(PORT, () => {
  console.log(`Minimal backend listening on http://localhost:${PORT}`);
});
