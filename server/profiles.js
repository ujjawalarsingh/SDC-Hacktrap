/**
 * Attacker Profile Management
 * Tracks behavioral patterns by IP address
 */

const profiles = new Map();

function getOrCreateProfile(ip) {
  if (!profiles.has(ip)) {
    profiles.set(ip, {
      ip,
      profile_id: `attacker_${ip.replace(/\./g, "_")}`,
      first_seen: new Date().toISOString(),
      last_seen: new Date().toISOString(),
      total_events: 0,
      attack_types: new Map(),
      average_risk_score: 0,
      risk_scores: [],
      dominant_attack_type: "Unknown",
      activity_pattern: "steady",
      threat_level: "Low",
    });
  }
  return profiles.get(ip);
}

function updateProfile(event) {
  const profile = getOrCreateProfile(event.ip);
  profile.last_seen = event.timestamp;
  profile.total_events += 1;

  const threatLabel =
    event.analysis?.threat_label || event.attack_type || "Unknown";
  profile.attack_types.set(
    threatLabel,
    (profile.attack_types.get(threatLabel) || 0) + 1,
  );

  const risk = event.analysis?.risk_score || event.risk_score || 0;
  profile.risk_scores.push(risk);
  if (profile.risk_scores.length > 100) {
    profile.risk_scores.shift();
  }

  profile.average_risk_score =
    profile.risk_scores.reduce((a, b) => a + b, 0) / profile.risk_scores.length;

  // Determine dominant attack type
  let maxCount = 0;
  for (const [type, count] of profile.attack_types.entries()) {
    if (count > maxCount) {
      maxCount = count;
      profile.dominant_attack_type = type;
    }
  }

  // Determine threat level
  if (profile.average_risk_score >= 85) {
    profile.threat_level = "High";
  } else if (profile.average_risk_score >= 65) {
    profile.threat_level = "Medium";
  } else {
    profile.threat_level = "Low";
  }

  // Determine activity pattern
  if (profile.total_events >= 10) {
    profile.activity_pattern = "persistent";
  } else if (profile.total_events >= 3) {
    profile.activity_pattern = "burst";
  }

  return profile;
}

function getProfileSummary(profile) {
  return {
    profile_id: profile.profile_id,
    ip: profile.ip,
    dominant_attack_type: profile.dominant_attack_type,
    activity_pattern: profile.activity_pattern,
    threat_level: profile.threat_level,
    total_events: profile.total_events,
    average_risk_score: Math.round(profile.average_risk_score),
    first_seen: profile.first_seen,
    last_seen: profile.last_seen,
  };
}

function getTopAttackers(limit = 5) {
  return [...profiles.values()]
    .sort((a, b) => b.total_events - a.total_events)
    .slice(0, limit)
    .map(getProfileSummary);
}

function getProfileByIP(ip) {
  const profile = profiles.get(ip);
  return profile ? getProfileSummary(profile) : null;
}

function getAllProfiles() {
  return [...profiles.values()].map(getProfileSummary);
}

function cleanupOldProfiles(maxAge = 600000) {
  // Remove profiles not seen for 10 minutes
  const cutoff = Date.now() - maxAge;
  for (const [ip, profile] of profiles.entries()) {
    if (new Date(profile.last_seen).getTime() < cutoff) {
      profiles.delete(ip);
    }
  }
}

module.exports = {
  getOrCreateProfile,
  updateProfile,
  getProfileSummary,
  getTopAttackers,
  getProfileByIP,
  getAllProfiles,
  cleanupOldProfiles,
};
