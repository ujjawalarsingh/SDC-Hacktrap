import L from 'leaflet';
import 'leaflet/dist/leaflet.css';
import { io } from 'socket.io-client';

const API_BASE = 'http://localhost:3001';
const FEED_LIMIT = 50;
const STATE_LIMIT = 200;

const feedEl = document.getElementById('feed');
const feedCountEl = document.getElementById('feedCount');
const logsBodyEl = document.getElementById('logsBody');
const searchInputEl = document.getElementById('searchInput');
const sortBtnEl = document.getElementById('sortBtn');
const total5mEl = document.getElementById('total5m');
const topCountryEl = document.getElementById('topCountry');
const topTypeEl = document.getElementById('topType');
const confidenceBarsEl = document.getElementById('confidenceBars');
const insightTextEl = document.getElementById('insightText');
const lastUpdateEl = document.getElementById('lastUpdate');

const countryCoords = {
  'United States': [39.8283, -98.5795],
  Russia: [61.524, 105.3188],
  China: [35.8617, 104.1954],
  Germany: [51.1657, 10.4515],
  India: [20.5937, 78.9629],
  Brazil: [-14.235, -51.9253],
  Netherlands: [52.1326, 5.2913],
  'United Kingdom': [55.3781, -3.436],
  Singapore: [1.3521, 103.8198],
  Japan: [36.2048, 138.2529],
  Canada: [56.1304, -106.3468],
  France: [46.2276, 2.2137],
};

let events = [];
let eventIds = new Set();
let sortDescending = true;
let insightIndex = 0;
let mapMarkers = [];

const map = L.map('map', {
  zoomControl: false,
  attributionControl: false,
}).setView([25, 5], 2);

L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
  maxZoom: 5,
  minZoom: 2,
}).addTo(map);

function scoreFor(event) {
  return event.analysis?.risk_score ?? event.risk_score ?? 0;
}

function confidenceFor(event) {
  return event.analysis?.confidence ?? 'Low';
}

function labelFor(event) {
  return event.analysis?.threat_label ?? event.attack_type ?? 'Unknown';
}

function badgeClassByConfidence(confidence) {
  if (confidence === 'High') return 'risk-high';
  if (confidence === 'Medium') return 'risk-medium';
  return 'risk-low';
}

function addEvent(nextEvent) {
  if (!nextEvent?.id || eventIds.has(nextEvent.id)) {
    return;
  }

  events.push(nextEvent);
  eventIds.add(nextEvent.id);

  if (events.length > STATE_LIMIT) {
    const removed = events.splice(0, events.length - STATE_LIMIT);
    for (const oldEvent of removed) {
      eventIds.delete(oldEvent.id);
    }
  }
}

function addEvents(batch) {
  for (const event of batch) {
    addEvent(event);
  }
}

function renderFeed() {
  const latest = [...events]
    .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
    .slice(0, FEED_LIMIT);

  feedCountEl.textContent = `${latest.length} events`;

  feedEl.innerHTML = latest
    .map((event) => {
      const confidence = confidenceFor(event);
      return `
        <article class="feed-item ${badgeClassByConfidence(confidence)}" data-id="${event.id}">
          <div class="row top">
            <strong>${event.ip}</strong>
            <span class="score">${scoreFor(event)}</span>
          </div>
          <div class="row mid">
            <span>${event.country || 'Unknown'}</span>
            <span>${labelFor(event)}</span>
          </div>
        </article>
      `;
    })
    .join('');

  if (feedEl.firstElementChild) {
    feedEl.firstElementChild.classList.add('new');
    setTimeout(() => {
      feedEl.firstElementChild?.classList.remove('new');
    }, 1200);
  }

  feedEl.scrollTop = 0;
}

function renderMap() {
  for (const marker of mapMarkers) {
    map.removeLayer(marker);
  }
  mapMarkers = [];

  const latest = [...events]
    .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
    .slice(0, 50);

  for (const event of latest) {
    const coords = countryCoords[event.country];
    if (!coords) continue;

    const marker = L.circleMarker(coords, {
      radius: 7,
      className: `pulse ${badgeClassByConfidence(confidenceFor(event))}`,
      color: '#9ca3af',
      fillOpacity: 0.85,
      weight: 1,
    })
      .addTo(map)
      .bindTooltip(`${event.ip} | ${labelFor(event)} | Risk ${scoreFor(event)}`);

    mapMarkers.push(marker);
  }
}

function countBy(items, keyGetter) {
  const map = new Map();
  for (const item of items) {
    const key = keyGetter(item) || 'Unknown';
    map.set(key, (map.get(key) || 0) + 1);
  }
  return map;
}

function topKey(countMap) {
  let top = '-';
  let max = -1;
  for (const [key, value] of countMap.entries()) {
    if (value > max) {
      top = key;
      max = value;
    }
  }
  return top;
}

function renderStats() {
  const now = Date.now();
  const fiveMin = events.filter((event) => now - new Date(event.timestamp).getTime() <= 300000);
  const countryCounts = countBy(fiveMin, (event) => event.country);
  const typeCounts = countBy(fiveMin, (event) => labelFor(event));

  total5mEl.textContent = String(fiveMin.length);
  topCountryEl.textContent = topKey(countryCounts);
  topTypeEl.textContent = topKey(typeCounts);
  lastUpdateEl.textContent = `Updated ${new Date().toLocaleTimeString()}`;

  const confidenceCounts = countBy(fiveMin, (event) => confidenceFor(event));
  const total = fiveMin.length || 1;
  const levels = ['High', 'Medium', 'Low'];

  confidenceBarsEl.innerHTML = levels
    .map((level) => {
      const value = confidenceCounts.get(level) || 0;
      const width = Math.max(6, (value / total) * 100);
      const cls = badgeClassByConfidence(level);
      return `
      <div class="bar-row">
        <span>${level}</span>
        <div class="bar-track"><div class="bar-fill ${cls}" style="width:${width}%"></div></div>
        <strong>${value}</strong>
      </div>`;
    })
    .join('');
}

function buildInsights() {
  const latest = [...events]
    .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
    .slice(0, 80);

  if (latest.length === 0) {
    return ['Telemetry initializing. AI engine calibrating risk baselines.'];
  }

  const high = latest.filter((event) => confidenceFor(event) === 'High');
  const malware = latest.filter((event) => labelFor(event) === 'Malware Activity');
  const bruteForce = latest.filter((event) => labelFor(event) === 'Brute Force');
  const topCountry = topKey(countBy(latest, (event) => event.country));

  const insights = [];

  if (high.length > 0) {
    insights.push(`High-severity cluster active: ${high.length} critical events in recent telemetry.`);
  }

  if (malware.length > bruteForce.length && malware.length > 0) {
    insights.push('Malware patterns increasing. Payload retrieval behavior is rising.');
  }

  if (bruteForce.length > 0) {
    insights.push(`Brute force pressure detected. ${bruteForce.length} coordinated login sequences observed.`);
  }

  if (topCountry !== '-') {
    insights.push(`Primary threat origin currently appears to be ${topCountry}.`);
  }

  insights.push('AI engine remains active and continuously reprioritizing incident risk.');
  return insights;
}

function rotateInsight() {
  const insights = buildInsights();
  if (insightIndex >= insights.length) {
    insightIndex = 0;
  }
  insightTextEl.textContent = insights[insightIndex];
  insightIndex += 1;
}

function renderTable() {
  const term = searchInputEl.value.trim().toLowerCase();
  let tableData = [...events]
    .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
    .slice(0, 120);

  if (term) {
    tableData = tableData.filter((event) => {
      const blob = [
        event.timestamp,
        event.ip,
        event.country,
        event.command,
        labelFor(event),
      ]
        .join(' ')
        .toLowerCase();
      return blob.includes(term);
    });
  }

  tableData.sort((a, b) => {
    const delta = scoreFor(a) - scoreFor(b);
    return sortDescending ? -delta : delta;
  });

  logsBodyEl.innerHTML = tableData
    .map((event) => {
      const confidence = confidenceFor(event);
      return `
      <tr class="${badgeClassByConfidence(confidence)}">
        <td>${new Date(event.timestamp).toLocaleTimeString()}</td>
        <td>${event.ip}</td>
        <td>${event.country || 'Unknown'}</td>
        <td>${labelFor(event)}</td>
        <td class="command">${event.command}</td>
        <td>${scoreFor(event)}</td>
      </tr>`;
    })
    .join('');
}

function renderAll() {
  renderFeed();
  renderMap();
  renderStats();
  renderTable();
}

async function loadInitialEvents() {
  try {
    const res = await fetch(`${API_BASE}/api/events?limit=100`);
    if (!res.ok) {
      throw new Error(`HTTP ${res.status}`);
    }

    const data = await res.json();
    addEvents(Array.isArray(data.events) ? data.events : []);
  } catch (_error) {
    // Keep UI active even if initial fetch fails.
  }

  renderAll();
}

function startSocket() {
  const socket = io(API_BASE, {
    transports: ['websocket', 'polling'],
  });

  socket.on('new_event', (event) => {
    addEvent(event);
    renderAll();
  });

  socket.on('connect_error', () => {
    // Silent fallback to polling below.
  });
}

let lastSince = null;
async function pollSinceFallback() {
  try {
    const url = lastSince
      ? `${API_BASE}/api/events?since=${encodeURIComponent(lastSince)}&limit=100`
      : `${API_BASE}/api/events?limit=20`;

    const res = await fetch(url);
    if (!res.ok) return;
    const data = await res.json();
    const batch = Array.isArray(data.events) ? data.events : [];
    addEvents(batch);

    if (events.length > 0) {
      const latestTs = [...events].sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))[0].timestamp;
      lastSince = latestTs;
    }

    renderAll();
  } catch (_error) {
    // Keep silent in fallback loop.
  }
}

sortBtnEl.addEventListener('click', () => {
  sortDescending = !sortDescending;
  sortBtnEl.textContent = `Sort by Risk: ${sortDescending ? 'Desc' : 'Asc'}`;
  renderTable();
});

searchInputEl.addEventListener('input', () => {
  renderTable();
});

await loadInitialEvents();
startSocket();

setInterval(() => {
  renderStats();
}, 3000);

setInterval(() => {
  rotateInsight();
}, 4000);

setInterval(() => {
  pollSinceFallback();
}, 5000);

rotateInsight();
