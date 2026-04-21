# Honeypot Dashboard (Minimal Local Mode)

This repository is refactored into a minimal local setup that runs without container tooling or external log ingestion.

## Project Structure

```
honeypot-dashboard/
├── frontend/
│   ├── index.html
│   ├── main.js
│   ├── package.json
│   └── styles.css
├── server/
│   ├── package.json
│   └── server.js
└── README.md
```

## Requirements

- Node.js 18+
- npm

## Run Locally

### 1. Start Backend

```bash
cd server
npm install
node server.js
```

Backend endpoint:

- GET http://localhost:3001/api/events

Example response:

```json
{
  "events": []
}
```

### 2. Start Frontend Dev Server

In a new terminal:

```bash
cd frontend
npm install
npm run dev
```

Open the Vite URL shown in the terminal (usually http://localhost:5173).

## Notes

- Frontend fetches from http://localhost:3001/api/events.
- If backend is unavailable, frontend falls back to a local mocked empty response.
- No container runtime, reverse proxy, scheduler, or external API dependencies are required.
