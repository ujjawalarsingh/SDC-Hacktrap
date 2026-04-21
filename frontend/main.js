import L from "leaflet";
import "leaflet/dist/leaflet.css";
import { io } from "socket.io-client";

const API_BASE = "http://localhost:3001";
const STATE_LIMIT = 200;
const FEED_LIMIT = 40;
const MAP_LIMIT = 28;
const TABLE_LIMIT = STATE_LIMIT;
const RENDER_DEBOUNCE_MS = 180;
const MAP_REFRESH_MS = 2500;
const POLL_MS = 5000;

const elements = {
  statusText: document.getElementById("statusText"),
  startBtn: document.getElementById("startBtn"),
  pauseBtn: document.getElementById("pauseBtn"),
  resetBtn: document.getElementById("resetBtn"),
  viewLogsBtn: document.getElementById("viewLogsBtn"),
  feed: document.getElementById("feed"),
  feedCount: document.getElementById("feedCount"),
  logsBody: document.getElementById("logsBody"),
  searchInput: document.getElementById("searchInput"),
  sortBtn: document.getElementById("sortBtn"),
  total5m: document.getElementById("total5m"),
  topCountry: document.getElementById("topCountry"),
  topType: document.getElementById("topType"),
  confidenceBars: document.getElementById("confidenceBars"),
  insightText: document.getElementById("insightText"),
  lastUpdate: document.getElementById("lastUpdate"),
  map: document.getElementById("map"),
  threatLevelBadge: document.getElementById("threatLevelBadge"),
  topAttackers: document.getElementById("topAttackers"),
  forecastIntent: document.getElementById("forecastIntent"),
  forecastNextAction: document.getElementById("forecastNextAction"),
  forecastStage: document.getElementById("forecastStage"),
  forecastConfidence: document.getElementById("forecastConfidence"),
};

const countryCoords = {
  "United States": [39.8283, -98.5795],
  Russia: [61.524, 105.3188],
  China: [35.8617, 104.1954],
  Germany: [51.1657, 10.4515],
  India: [20.5937, 78.9629],
  Brazil: [-14.235, -51.9253],
  Netherlands: [52.1326, 5.2913],
  "United Kingdom": [55.3781, -3.436],
  Singapore: [1.3521, 103.8198],
  Japan: [36.2048, 138.2529],
  Canada: [56.1304, -106.3468],
  France: [46.2276, 2.2137],
};

const map = L.map(elements.map, {
  zoomControl: false,
  attributionControl: false,
  worldCopyJump: false,
  scrollWheelZoom: false,
  doubleClickZoom: false,
  boxZoom: false,
  keyboard: false,
  tap: false,
}).setView([24, 5], 2);

L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
  maxZoom: 4,
  minZoom: 2,
  updateWhenIdle: true,
}).addTo(map);

const state = {
  events: [],
  ids: new Set(),
  isRunning: false,
  sortDescending: true,
  recentInsightIndex: 0,
  renderQueued: false,
  mapQueued: false,
  pollTimer: null,
  statsTimer: null,
  insightTimer: null,
  mapTimer: null,
  statusTimer: null,
  socket: null,
  lastSeenTimestamp: null,
  markers: [],
  markerPool: [],
  insightLines: ["System Ready - Click Start"],
  systemThreatLevel: "Low",
  topAttackers: [],
  forecast: {
    intent: "Awaiting data",
    predictedNextAction: "Awaiting data",
    stage: "Initial",
    intentConfidence: "Low",
  },
};

function scoreFor(event) {
  return event.analysis?.risk_score ?? event.risk_score ?? 0;
}

function confidenceFor(event) {
  return event.analysis?.confidence ?? "Low";
}

function labelFor(event) {
  return event.analysis?.threat_label ?? event.attack_type ?? "Unknown";
}

function levelClass(event) {
  const confidence = confidenceFor(event);
  if (confidence === "High") return "high";
  if (confidence === "Medium") return "medium";
  return "low";
}

function isoTime(event) {
  return new Date(event.timestamp).toLocaleTimeString();
}

function trimState() {
  if (state.events.length <= STATE_LIMIT) return;
  const overflow = state.events.splice(0, state.events.length - STATE_LIMIT);
  for (const oldEvent of overflow) {
    state.ids.delete(oldEvent.id);
  }
}

function addEvent(event) {
  if (!event?.id || state.ids.has(event.id)) return false;
  state.events.push(event);
  state.ids.add(event.id);
  trimState();
  state.lastSeenTimestamp = event.timestamp;
  return true;
}

function addEvents(batch) {
  let added = false;
  for (const event of batch) {
    if (addEvent(event)) added = true;
  }
  return added;
}

function clearState() {
  state.events = [];
  state.ids.clear();
  state.lastSeenTimestamp = null;
  state.recentInsightIndex = 0;
  for (const marker of state.markers) {
    marker.remove();
  }
  state.markerPool.push(...state.markers);
  state.markers = [];
  state.renderQueued = false;
  state.mapQueued = false;
  elements.feed.innerHTML = `
    <div class="empty-state">
      <div class="empty-title">System Ready - Click Start</div>
      <div class="empty-copy">Live telemetry is paused for presentation mode.</div>
    </div>`;
  elements.logsBody.innerHTML = "";
  elements.feedCount.textContent = "0 events";
  elements.total5m.textContent = "0";
  elements.topCountry.textContent = "-";
  elements.topType.textContent = "-";
  elements.confidenceBars.innerHTML = "";
  elements.insightText.textContent = "System Ready - Click Start";
  elements.lastUpdate.textContent = "Paused";
  state.insightLines = ["System Ready - Click Start"];
  state.forecast = {
    intent: "Awaiting data",
    predictedNextAction: "Awaiting data",
    stage: "Initial",
    intentConfidence: "Low",
  };
  renderForecast();
  updateMap(true);
}

function activateRunningState(nextRunning) {
  state.isRunning = nextRunning;
  elements.statusText.textContent = nextRunning ? "RUNNING" : "PAUSED";
  elements.startBtn.disabled = nextRunning;
  elements.pauseBtn.disabled = !nextRunning;
}

function riskClass(score) {
  if (score >= 85) return "high";
  if (score >= 65) return "medium";
  return "low";
}

function countBy(items, keyGetter) {
  const counts = new Map();
  for (const item of items) {
    const key = keyGetter(item) || "Unknown";
    counts.set(key, (counts.get(key) || 0) + 1);
  }
  return counts;
}

function topKey(countMap) {
  let top = "-";
  let max = -1;
  for (const [key, value] of countMap.entries()) {
    if (value > max) {
      top = key;
      max = value;
    }
  }
  return top;
}

function recentEvents() {
  const now = Date.now();
  return state.events.filter(
    (event) => now - new Date(event.timestamp).getTime() <= 300000,
  );
}

function updateStats() {
  const fiveMinuteEvents = recentEvents();
  const countryCounts = countBy(fiveMinuteEvents, (event) => event.country);
  const threatCounts = countBy(fiveMinuteEvents, (event) => labelFor(event));
  const confidenceCounts = countBy(fiveMinuteEvents, (event) =>
    confidenceFor(event),
  );

  elements.total5m.textContent = String(fiveMinuteEvents.length);
  elements.topCountry.textContent = topKey(countryCounts);
  elements.topType.textContent = topKey(threatCounts);
  elements.lastUpdate.textContent = state.isRunning
    ? `Updated ${new Date().toLocaleTimeString()}`
    : "Paused";

  const total = fiveMinuteEvents.length || 1;
  const levels = ["High", "Medium", "Low"];
  elements.confidenceBars.innerHTML = levels
    .map((level) => {
      const value = confidenceCounts.get(level) || 0;
      const width = Math.max(8, (value / total) * 100);
      return `
        <div class="bar-row ${level.toLowerCase()}">
          <span>${level}</span>
          <div class="bar-track"><div class="bar-fill" style="width:${width}%"></div></div>
          <strong>${value}</strong>
        </div>`;
    })
    .join("");

  const topCountries = [...countryCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 3)
    .map(([country, count]) => `${country} (${count})`);

  state.insightLines = buildInsights(fiveMinuteEvents, topCountries);
}

function buildInsights(fiveMinuteEvents, topCountries) {
  if (fiveMinuteEvents.length === 0) {
    return ["System Ready - Click Start"];
  }

  const highCount = fiveMinuteEvents.filter(
    (event) => confidenceFor(event) === "High",
  ).length;
  const malwareCount = fiveMinuteEvents.filter(
    (event) => labelFor(event) === "Malware Activity",
  ).length;
  const bruteCount = fiveMinuteEvents.filter(
    (event) => labelFor(event) === "Brute Force",
  ).length;
  const reconCount = fiveMinuteEvents.filter(
    (event) => labelFor(event) === "Reconnaissance",
  ).length;

  const lines = [];

  if (highCount > 0) {
    lines.push(`High risk activity active: ${highCount} events.`);
  }

  if (bruteCount >= malwareCount && bruteCount > 0) {
    lines.push(
      `Brute force activity detected from ${topKey(countBy(fiveMinuteEvents, (event) => event.country))}.`,
    );
  }

  if (malwareCount > 0) {
    lines.push(
      `Malware patterns increasing: ${malwareCount} payload-style commands observed.`,
    );
  }

  if (reconCount > 0) {
    lines.push(
      `Reconnaissance traffic remains active across ${reconCount} events.`,
    );
  }

  // Behavioral intelligence insights
  if (state.topAttackers.length > 0) {
    const topAttacker = state.topAttackers[0];
    if (topAttacker.activity_pattern === "persistent") {
      lines.push(
        `Persistent threat detected from ${topAttacker.ip}: ${topAttacker.total_events} events (${topAttacker.dominant_attack_type}).`,
      );
    } else if (topAttacker.activity_pattern === "burst") {
      lines.push(
        `Burst attack detected from ${topAttacker.ip}: rapid escalation observed.`,
      );
    }
  }

  if (topCountries.length > 0) {
    lines.push(`Top sources: ${topCountries.join(", ")}.`);
  }

  if (state.forecast.intent === "Account Takeover") {
    lines.push("Attacker likely attempting system takeover.");
  }

  if (
    state.forecast.predictedNextAction.toLowerCase().includes("execution") ||
    state.forecast.intent === "Malware Deployment"
  ) {
    lines.push("Malware execution expected next.");
  }

  if (state.forecast.stage === "Critical") {
    lines.push("Critical escalation detected in active session.");
  }

  const threatMsg = `Threat Level: ${state.systemThreatLevel.toUpperCase()}`;
  lines.push(`AI Engine Active. ${threatMsg}`);
  return lines;
}

function renderFeed() {
  const latest = [...state.events]
    .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
    .slice(0, FEED_LIMIT);

  elements.feedCount.textContent = `${latest.length} live events`;
  if (latest.length === 0) {
    if (state.isRunning) {
      elements.feed.innerHTML = `
      <div class="empty-state">
        <div class="empty-title">Connecting Live Telemetry</div>
        <div class="empty-copy">Syncing events and awaiting the next threat signal.</div>
      </div>`;
      return;
    }

    elements.feed.innerHTML = `
      <div class="empty-state">
        <div class="empty-title">System Ready - Click Start</div>
        <div class="empty-copy">Live telemetry is paused for presentation mode.</div>
      </div>`;
    return;
  }

  elements.feed.innerHTML = latest
    .map((event) => {
      const score = scoreFor(event);
      const cls = riskClass(score);
      const highlight = cls === "high" ? " glow" : "";
      return `
        <article class="feed-item ${cls}${highlight}">
          <div class="row top">
            <strong>${event.ip}</strong>
            <span class="score ${cls}">${score}</span>
          </div>
          <div class="row mid">
            <span>${event.country || "Unknown"}</span>
            <span>${labelFor(event)}</span>
          </div>
        </article>`;
    })
    .join("");
}

function getMapMarker(event) {
  let marker = state.markerPool.pop();
  if (!marker) {
    marker = L.circleMarker([0, 0], {
      radius: 5,
      weight: 1,
      fillOpacity: 0.65,
      opacity: 0.85,
      interactive: true,
    }).addTo(map);
  }
  return marker;
}

function updateMap(force = false) {
  if (!state.isRunning && !force) return;

  const latest = [...state.events]
    .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
    .slice(0, MAP_LIMIT);

  while (state.markers.length > latest.length) {
    const marker = state.markers.pop();
    marker.remove();
    state.markerPool.push(marker);
  }

  latest.forEach((event, index) => {
    const coords = countryCoords[event.country];
    if (!coords) return;

    let marker = state.markers[index];
    if (!marker) {
      marker = getMapMarker(event);
      state.markers[index] = marker;
    }

    marker.setLatLng(coords);
    marker.setStyle({
      color:
        event.analysis?.confidence === "High"
          ? "#ff4d4f"
          : event.analysis?.confidence === "Medium"
            ? "#f5c542"
            : "#22c55e",
      fillColor:
        event.analysis?.confidence === "High"
          ? "#ff4d4f"
          : event.analysis?.confidence === "Medium"
            ? "#f5c542"
            : "#22c55e",
      radius: event.analysis?.confidence === "High" ? 8 : 6,
    });
    marker.bindTooltip(
      `${event.ip} | ${labelFor(event)} | ${scoreFor(event)}`,
      { direction: "top" },
    );
  });
}

function renderTable() {
  const query = elements.searchInput.value.trim().toLowerCase();
  let rows = [...state.events]
    .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
    .slice(0, TABLE_LIMIT);

  if (query) {
    rows = rows.filter((event) => {
      const blob = [
        event.timestamp,
        event.ip,
        event.country,
        event.command,
        labelFor(event),
      ]
        .join(" ")
        .toLowerCase();
      return blob.includes(query);
    });
  }

  rows.sort((a, b) => {
    const delta = scoreFor(a) - scoreFor(b);
    return state.sortDescending ? -delta : delta;
  });

  elements.logsBody.innerHTML = rows
    .map((event) => {
      const cls = riskClass(scoreFor(event));
      return `
        <tr class="${cls}">
          <td>${isoTime(event)}</td>
          <td>${event.ip}</td>
          <td>${event.country || "Unknown"}</td>
          <td>${labelFor(event)}</td>
          <td class="command">${event.command}</td>
          <td>${scoreFor(event)}</td>
        </tr>`;
    })
    .join("");
}

function renderInsights() {
  const lines =
    state.insightLines.length > 0
      ? state.insightLines
      : ["System Ready - Click Start"];
  const line = lines[state.recentInsightIndex % lines.length];
  state.recentInsightIndex += 1;
  elements.insightText.textContent = line;
}

function stageClass(stage) {
  if (stage === "Critical") return "stage-critical";
  if (stage === "Escalating") return "stage-escalating";
  return "stage-initial";
}

function updateForecastFromEvents() {
  const latestByTime = [...state.events].sort(
    (a, b) => new Date(b.timestamp) - new Date(a.timestamp),
  );
  const latest = latestByTime.find(
    (event) =>
      event.analysis?.intent ||
      event.analysis?.predicted_next_action ||
      event.analysis?.stage,
  );

  if (!latest) {
    return;
  }

  state.forecast = {
    intent: latest.analysis?.intent || "Suspicious Probing",
    predictedNextAction:
      latest.analysis?.predicted_next_action || "Likely lateral probing",
    stage: latest.analysis?.stage || "Initial",
    intentConfidence: latest.analysis?.intent_confidence || "Low",
  };
}

function renderForecast() {
  elements.forecastIntent.textContent = state.forecast.intent;
  elements.forecastNextAction.textContent = state.forecast.predictedNextAction;
  elements.forecastConfidence.textContent = state.forecast.intentConfidence;
  elements.forecastStage.textContent = state.forecast.stage;
  elements.forecastStage.className = `forecast-stage ${stageClass(state.forecast.stage)}`;
}

function renderFrame() {
  state.renderQueued = false;
  renderFeed();
  renderTable();
  updateForecastFromEvents();
  renderForecast();
  updateStats();
  renderInsights();
}

function queueRender() {
  if (state.renderQueued) return;
  state.renderQueued = true;
  setTimeout(renderFrame, RENDER_DEBOUNCE_MS);
}

function queueMapUpdate() {
  if (state.mapQueued) return;
  state.mapQueued = true;
  setTimeout(() => {
    state.mapQueued = false;
    updateMap();
  }, MAP_REFRESH_MS);
}

async function fetchSnapshot() {
  try {
    const res = await fetch(`${API_BASE}/api/events?limit=100`);
    if (!res.ok) return;
    const data = await res.json();
    addEvents(Array.isArray(data.events) ? data.events.slice().reverse() : []);
  } catch (_error) {
    // keep quiet in demo mode
  }
}

async function syncSince() {
  if (!state.isRunning) return;
  try {
    const url = state.lastSeenTimestamp
      ? `${API_BASE}/api/events?since=${encodeURIComponent(state.lastSeenTimestamp)}&limit=100`
      : `${API_BASE}/api/events?limit=20`;
    const res = await fetch(url);
    if (!res.ok) return;
    const data = await res.json();
    if (addEvents(Array.isArray(data.events) ? data.events.reverse() : [])) {
      queueRender();
      queueMapUpdate();
    }
  } catch (_error) {
    // ignore polling fallback errors
  }
}

async function fetchSystemStatus() {
  if (!state.isRunning) return;
  try {
    const res = await fetch(`${API_BASE}/api/system-status`);
    if (!res.ok) return;
    const data = await res.json();
    state.systemThreatLevel = data.threat_level || "Low";
    state.topAttackers = data.top_attackers || [];
    updateThreatLevel();
    renderTopAttackers();
  } catch (_error) {
    // ignore errors
  }
}

function updateThreatLevel() {
  const badge = elements.threatLevelBadge;
  const level = state.systemThreatLevel;
  badge.textContent = `Threat Level: ${level.toUpperCase()}`;
  badge.className = `threat-badge threat-${level.toLowerCase()}`;
}

function renderTopAttackers() {
  const attackers = state.topAttackers.slice(0, 3);
  if (attackers.length === 0) {
    elements.topAttackers.innerHTML =
      '<div class="empty-copy">No active attackers</div>';
    return;
  }

  elements.topAttackers.innerHTML = attackers
    .map(
      (attacker) =>
        `<div class="attacker-card">
          <div class="attacker-ip">${attacker.ip}</div>
          <div class="attacker-type">${attacker.dominant_attack_type}</div>
          <div class="attacker-risk risk-${attacker.threat_level.toLowerCase()}">
            ${attacker.threat_level} (${attacker.average_risk_score}/100)
          </div>
          <div class="attacker-meta">
            ${attacker.total_events} events | ${attacker.activity_pattern}
          </div>
        </div>`,
    )
    .join("");
}

function processIncoming(event) {
  if (!state.isRunning) return;
  if (addEvent(event)) {
    queueRender();
    queueMapUpdate();
  }
}

function connectRealtime() {
  state.socket = io(API_BASE, { transports: ["websocket", "polling"] });
  state.socket.on("new_event", processIncoming);
  state.socket.on("connect_error", () => {});
}

function startRunning() {
  if (state.isRunning) return;
  activateRunningState(true);
  elements.insightText.textContent = "System Ready - Streaming live telemetry.";
  elements.feed.innerHTML = `
    <div class="empty-state">
      <div class="empty-title">Connecting Live Telemetry</div>
      <div class="empty-copy">Syncing events and awaiting the next threat signal.</div>
    </div>`;
  elements.lastUpdate.textContent = "Syncing...";
  queueRender();
  queueMapUpdate();
  fetchSnapshot().then(() => {
    queueRender();
    queueMapUpdate();
  });
  fetchSystemStatus();
  syncSince();
}

function pauseRunning() {
  if (!state.isRunning) return;
  activateRunningState(false);
  elements.insightText.textContent = "Paused - click Start to resume live telemetry.";
}

function resetSystem() {
  pauseRunning();
  clearState();
}

elements.startBtn.addEventListener("click", startRunning);
elements.pauseBtn.addEventListener("click", pauseRunning);
elements.resetBtn.addEventListener("click", resetSystem);
elements.viewLogsBtn.addEventListener("click", () => {
  const logsPanel = document.querySelector(".bottom");
  const tableWrap = document.querySelector(".table-wrap");
  logsPanel?.scrollIntoView({ behavior: "smooth", block: "start" });
  if (tableWrap) {
    tableWrap.scrollTop = 0;
  }
  elements.searchInput?.focus();
});
elements.searchInput.addEventListener("input", queueRender);
elements.sortBtn.addEventListener("click", () => {
  state.sortDescending = !state.sortDescending;
  elements.sortBtn.textContent = `Sort by Risk: ${state.sortDescending ? "Desc" : "Asc"}`;
  renderTable();
});

activateRunningState(false);
clearState();
connectRealtime();

queueRender();

state.pollTimer = setInterval(syncSince, POLL_MS);
state.statsTimer = setInterval(() => {
  if (state.isRunning) updateStats();
}, 3000);
state.insightTimer = setInterval(() => {
  if (state.isRunning) renderInsights();
}, 3500);
state.statusTimer = setInterval(() => {
  if (state.isRunning) fetchSystemStatus();
}, 4000);
state.mapTimer = setInterval(() => {
  if (state.isRunning) updateMap();
}, MAP_REFRESH_MS);
