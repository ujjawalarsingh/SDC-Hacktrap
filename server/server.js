const express = require("express");
const cors = require("cors");
const http = require("http");
const { Server } = require("socket.io");
const { startEventGenerator } = require("./generator");
const {
  updateProfile,
  getTopAttackers,
  getProfileByIP,
  cleanupOldProfiles,
} = require("./profiles");

const app = express();
const PORT = process.env.PORT || 3001;
const events = [];
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*",
  },
});

// Start generator with profile updater
startEventGenerator(events, (event) => {
  try {
    io.emit("new_event", event);
  } catch (error) {
    console.error("Socket emission error:", error.message);
  }
}, updateProfile);

app.use(cors());

io.on("connection", (socket) => {
  console.log(`Socket connected: ${socket.id}`);
});

// Compute system threat level
function computeSystemThreatLevel() {
  const now = Date.now();
  const tenSecondsAgo = now - 10000;
  
  const highRiskEvents = events.filter(
    (event) => 
      new Date(event.timestamp).getTime() > tenSecondsAgo &&
      (event.analysis?.risk_score || event.risk_score || 0) >= 85
  );

  if (highRiskEvents.length >= 5) return "High";
  
  const mediumRiskEvents = events.filter(
    (event) => 
      new Date(event.timestamp).getTime() > tenSecondsAgo &&
      (event.analysis?.risk_score || event.risk_score || 0) >= 65
  );

  if (mediumRiskEvents.length >= 3) return "Medium";
  
  return "Low";
}

// Periodic cleanup
setInterval(() => {
  cleanupOldProfiles(600000); // 10 minutes
}, 60000); // Every minute

// REST API: Get events with filtering
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

// NEW: System status with threat level
app.get("/api/system-status", (req, res) => {
  const threatLevel = computeSystemThreatLevel();
  const topAttackers = getTopAttackers(5);
  const totalEvents = events.length;

  res.json({
    threat_level: threatLevel,
    total_events: totalEvents,
    top_attackers: topAttackers,
    timestamp: new Date().toISOString(),
  });
});

// NEW: Get top attackers
app.get("/api/attackers", (req, res) => {
  const limit = Math.min(Math.max(1, Number.parseInt(req.query.limit || 10)), 50);
  const attackers = getTopAttackers(limit);
  res.json({ attackers });
});

// NEW: Get specific attacker profile
app.get("/api/attackers/:ip", (req, res) => {
  const profile = getProfileByIP(req.params.ip);
  if (!profile) {
    return res.status(404).json({ error: "Attacker profile not found" });
  }
  res.json({ profile });
});

server.listen(PORT, () => {
  console.log(`Minimal backend listening on http://localhost:${PORT}`);
});
