function randomInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function clamp(value, min, max) {
  return Math.max(min, Math.min(value, max));
}

function countSameIpWithinWindow(event, recentEvents, windowMs) {
  const currentTs = new Date(event.timestamp).getTime();
  if (Number.isNaN(currentTs)) {
    return 0;
  }

  return recentEvents.filter((candidate) => {
    if (candidate.ip !== event.ip) {
      return false;
    }

    const candidateTs = new Date(candidate.timestamp).getTime();
    if (Number.isNaN(candidateTs)) {
      return false;
    }

    const delta = currentTs - candidateTs;
    return delta >= 0 && delta <= windowMs;
  }).length;
}

function normalizeCommand(value) {
  return String(value || "").toLowerCase();
}

function isCommandExecution(command) {
  return (
    command.includes("whoami") ||
    command.includes("pwd") ||
    command.includes("ls") ||
    command.includes("cat ") ||
    command.includes("cd ")
  );
}

function getSessionEvents(event, recentEvents) {
  if (!event?.session_id) {
    return [];
  }

  return recentEvents
    .filter((candidate) => candidate.session_id === event.session_id)
    .sort(
      (a, b) =>
        new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime(),
    );
}

function confidenceFromScore(score) {
  if (score >= 80) return "High";
  if (score >= 55) return "Medium";
  return "Low";
}

function computeConsistencyBonus(event, recentEvents) {
  const sameIpRecent = recentEvents
    .filter((candidate) => candidate.ip === event.ip)
    .slice(-5);

  if (sameIpRecent.length < 2) {
    return 0;
  }

  const labels = sameIpRecent.map(
    (candidate) => candidate.analysis?.threat_label || candidate.attack_type,
  );
  const unique = new Set(labels);

  // Repeated pattern raises confidence, abrupt behavior changes reduce it.
  if (unique.size <= 2) {
    return 15;
  }

  if (unique.size >= 4) {
    return -12;
  }

  return 0;
}

function detectIntent(event, recentEvents, sessionEvents) {
  const command = normalizeCommand(event.command);
  const hasWgetOrCurl = command.includes("wget") || command.includes("curl");
  const hasChmod = command.includes("chmod");

  const sessionCommands = sessionEvents.map((candidate) =>
    normalizeCommand(candidate.command),
  );
  const hasBruteForceInSession = sessionEvents.some((candidate) => {
    const label = candidate.analysis?.threat_label || candidate.attack_type;
    return label === "Brute Force" || candidate.attack_type === "Brute Force";
  });
  const hasLoginOrCommandInSession = sessionCommands.some(
    (candidateCommand) =>
      candidateCommand.includes("ssh") ||
      candidateCommand.includes("cd /home") ||
      isCommandExecution(candidateCommand),
  );
  const hasScanPattern =
    event.attack_type === "Scan" || command.includes("nmap") || command.includes("nc ");

  let intent = "Suspicious Probing";
  let score = 48;

  if (hasWgetOrCurl || hasChmod || sessionCommands.some((candidate) => candidate.includes("chmod"))) {
    intent = "Malware Deployment";
    score = hasWgetOrCurl && (hasChmod || sessionCommands.some((candidate) => candidate.includes("chmod"))) ? 90 : 78;
  } else if (hasBruteForceInSession && hasLoginOrCommandInSession) {
    intent = "Account Takeover";
    score = 82;
  } else if (hasScanPattern) {
    intent = "Reconnaissance";
    score = 64;
  }

  score += computeConsistencyBonus(event, recentEvents);
  score = clamp(score, 0, 100);

  return {
    intent,
    intent_confidence: confidenceFromScore(score),
  };
}

function detectStage(event, sessionEvents) {
  const sessionCommands = sessionEvents.map((candidate) =>
    normalizeCommand(candidate.command),
  );

  const hasBruteForce = sessionEvents.some((candidate) => {
    const label = candidate.analysis?.threat_label || candidate.attack_type;
    return label === "Brute Force" || candidate.attack_type === "Brute Force";
  });
  const hasCommandExecution = sessionCommands.some((command) =>
    isCommandExecution(command),
  );
  const hasMalware = sessionCommands.some(
    (command) => command.includes("wget") || command.includes("curl") || command.includes("chmod"),
  );

  if (hasBruteForce && hasCommandExecution && hasMalware) {
    return "Critical";
  }

  if ((hasBruteForce && hasCommandExecution) || (hasBruteForce && hasMalware)) {
    return "Escalating";
  }

  return "Initial";
}

function predictNextAction(event, stage, intent) {
  const command = normalizeCommand(event.command);

  if (command.includes("wget") || command.includes("curl")) {
    return "Likely execution attempt";
  }

  if (intent === "Account Takeover" || event.attack_type === "Brute Force") {
    return "Likely login success attempt";
  }

  if (stage === "Escalating") {
    return "Likely malware deployment attempt";
  }

  if (intent === "Reconnaissance") {
    return "Likely credential attack attempt";
  }

  return "Likely lateral probing";
}

function detectThreatLabel(event, sameIpCountLast10s) {
  const command = String(event.command || "").toLowerCase();

  const isMalwareActivity =
    command.includes("wget") || command.includes("curl");
  if (isMalwareActivity) {
    return "Malware Activity";
  }

  const isBruteForce = sameIpCountLast10s >= 3;
  if (isBruteForce) {
    return "Brute Force";
  }

  const isReconnaissance = event.attack_type === "Scan" || event.port !== 22;
  if (isReconnaissance) {
    return "Reconnaissance";
  }

  return "Suspicious Activity";
}

function confidenceFromRisk(riskScore) {
  if (riskScore >= 85) {
    return "High";
  }

  if (riskScore >= 65) {
    return "Medium";
  }

  return "Low";
}

function analyzeEvent(event, recentEvents) {
  const safeRecentEvents = Array.isArray(recentEvents) ? recentEvents : [];
  const sameIpCountLast10s = countSameIpWithinWindow(
    event,
    safeRecentEvents,
    10000,
  );
  const threatLabel = detectThreatLabel(event, sameIpCountLast10s);

  let riskScore = randomInt(40, 70);
  if (threatLabel === "Malware Activity") {
    riskScore += 20;
  }

  if (threatLabel === "Brute Force") {
    riskScore += 15;
  }

  if (sameIpCountLast10s > 3) {
    riskScore += 10;
  }

  riskScore = clamp(riskScore, 0, 100);

  const sessionEvents = getSessionEvents(event, safeRecentEvents);
  const { intent, intent_confidence } = detectIntent(
    event,
    safeRecentEvents,
    sessionEvents,
  );
  const stage = detectStage(event, sessionEvents);
  const predicted_next_action = predictNextAction(event, stage, intent);

  return {
    threat_label: threatLabel,
    risk_score: riskScore,
    confidence: confidenceFromRisk(riskScore),
    intent,
    intent_confidence,
    stage,
    predicted_next_action,
  };
}

module.exports = { analyzeEvent };
