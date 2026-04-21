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

  return {
    threat_label: threatLabel,
    risk_score: riskScore,
    confidence: confidenceFromRisk(riskScore),
  };
}

module.exports = { analyzeEvent };
