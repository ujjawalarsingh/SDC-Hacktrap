const express = require("express");
const cors = require("cors");
const http = require("http");
const { Server } = require("socket.io");
const { startEventGenerator } = require("./generator");

const app = express();
const PORT = process.env.PORT || 3001;
const events = [];
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*",
  },
});

startEventGenerator(events, (event) => {
  try {
    io.emit("new_event", event);
  } catch (error) {
    console.error("Socket emission error:", error.message);
  }
});

app.use(cors());

io.on("connection", (socket) => {
  console.log(`Socket connected: ${socket.id}`);
});

app.get("/api/events", (req, res) => {
  const rawLimit = Number.parseInt(req.query.limit, 10);
  const limit = Number.isNaN(rawLimit)
    ? 50
    : Math.max(1, Math.min(rawLimit, 100));
  const since = req.query.since;

  let filtered = events;
  if (since) {
    const sinceDate = new Date(since);
    if (Number.isNaN(sinceDate.getTime())) {
      res.json({ events: [] });
      return;
    }

    filtered = events.filter((event) => new Date(event.timestamp) > sinceDate);
  }

  const latest = [...filtered]
    .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
    .slice(0, limit);

  res.json({ events: latest });
});

server.listen(PORT, () => {
  console.log(`Minimal backend listening on http://localhost:${PORT}`);
});
