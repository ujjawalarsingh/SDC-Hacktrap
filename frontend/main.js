const eventsEl = document.getElementById("events");

async function loadEvents() {
  const fallback = { events: [] };

  try {
    const res = await fetch("http://localhost:3001/api/events");
    if (!res.ok) {
      throw new Error(`HTTP ${res.status}`);
    }

    const data = await res.json();
    eventsEl.textContent = JSON.stringify(data, null, 2);
  } catch (_err) {
    eventsEl.textContent = JSON.stringify(fallback, null, 2);
  }
}

loadEvents();
