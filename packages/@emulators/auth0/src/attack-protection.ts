import type { Store } from "@emulators/core";
import { nowUnix } from "./helpers.js";
import { getAuth0Store } from "./store.js";
import { recordLog, dispatchEvent } from "./events.js";

// Attack-protection configuration. Defaults mirror Auth0's out-of-the-box
// posture (brute-force and suspicious-IP enabled, breached-password on).
export interface AttackProtectionConfig {
  bruteForce: {
    enabled: boolean;
    max_attempts: number;
    mode: "count_per_identifier_and_ip" | "count_per_identifier";
  };
  suspiciousIp: {
    enabled: boolean;
    max_attempts: number;
    // Sliding window in seconds for per-IP throttling.
    window_seconds: number;
  };
  breachedPassword: {
    enabled: boolean;
    // Seedable list of known-breached passwords for deterministic tests.
    passwords: string[];
  };
  botDetection: {
    enabled: boolean;
  };
}

function defaultConfig(): AttackProtectionConfig {
  return {
    bruteForce: { enabled: true, max_attempts: 10, mode: "count_per_identifier_and_ip" },
    suspiciousIp: { enabled: true, max_attempts: 100, window_seconds: 86400 },
    breachedPassword: { enabled: true, passwords: ["password", "123456", "qwerty"] },
    botDetection: { enabled: false },
  };
}

export function getAttackConfig(store: Store): AttackProtectionConfig {
  let cfg = store.getData<AttackProtectionConfig>("auth0.attackProtection.config");
  if (!cfg) {
    cfg = defaultConfig();
    // Merge any breached passwords seeded before this config was initialized.
    const seeded = store.getData<string[]>("auth0.seed.breachedPasswords");
    if (seeded && seeded.length > 0) cfg.breachedPassword.passwords = seeded;
    store.setData("auth0.attackProtection.config", cfg);
  }
  return cfg;
}

export function setAttackConfig(store: Store, cfg: AttackProtectionConfig): void {
  store.setData("auth0.attackProtection.config", cfg);
}

// Failed-attempt counters keyed by "{identifier}|{ip}" (brute force) and by IP
// alone (suspicious-ip). Stored as plain objects in Store data.
interface AttemptRecord {
  count: number;
  windowStart: number;
}

function getCounters(store: Store, key: string): Map<string, AttemptRecord> {
  let map = store.getData<Map<string, AttemptRecord>>(key);
  if (!map) {
    map = new Map();
    store.setData(key, map);
  }
  return map;
}

const bfKey = "auth0.attackProtection.bruteForce";
const ipKey = "auth0.attackProtection.suspiciousIp";

export function isBreachedPassword(store: Store, password: string): boolean {
  const cfg = getAttackConfig(store);
  if (!cfg.breachedPassword.enabled) return false;
  return cfg.breachedPassword.passwords.includes(password);
}

// Return true if the (identifier, ip) pair is currently blocked by brute-force
// protection, or the IP is throttled by suspicious-IP protection.
export function isBlocked(store: Store, identifier: string, ip: string): boolean {
  const as = getAuth0Store(store);
  if (as.userBlocks.findBy("identifier", identifier).some((b) => b.ip === ip || b.reason === "brute_force")) {
    return true;
  }

  const cfg = getAttackConfig(store);
  if (cfg.suspiciousIp.enabled) {
    const counter = getCounters(store, ipKey).get(ip);
    const now = nowUnix();
    if (counter && now - counter.windowStart < cfg.suspiciousIp.window_seconds) {
      if (counter.count >= cfg.suspiciousIp.max_attempts) return true;
    }
  }
  return false;
}

// Record a failed authentication attempt. Raises a user block once the
// configured thresholds are crossed, emitting the matching log + event.
export async function recordFailedAttempt(
  store: Store,
  identifier: string,
  ip: string,
  clientId: string | null,
): Promise<void> {
  const cfg = getAttackConfig(store);
  const now = nowUnix();
  const as = getAuth0Store(store);

  if (cfg.bruteForce.enabled) {
    const key = cfg.bruteForce.mode === "count_per_identifier" ? identifier : `${identifier}|${ip}`;
    const counters = getCounters(store, bfKey);
    const rec = counters.get(key) ?? { count: 0, windowStart: now };
    rec.count += 1;
    counters.set(key, rec);

    if (rec.count >= cfg.bruteForce.max_attempts) {
      const alreadyBlocked = as.userBlocks
        .findBy("identifier", identifier)
        .some((b) => b.ip === ip && b.reason === "brute_force");
      if (!alreadyBlocked) {
        as.userBlocks.insert({ identifier, ip, reason: "brute_force", created_at_unix: now });
        await recordLog(store, {
          type: "limit_wc",
          description: "Blocked account due to too many failed login attempts",
          clientId,
          ip,
        });
        await dispatchEvent(store, {
          type: "user.blocked",
          data: { identifier, ip, reason: "brute_force" },
        });
      }
    }
  }

  if (cfg.suspiciousIp.enabled) {
    const counters = getCounters(store, ipKey);
    const rec = counters.get(ip);
    if (!rec || now - rec.windowStart >= cfg.suspiciousIp.window_seconds) {
      counters.set(ip, { count: 1, windowStart: now });
    } else {
      rec.count += 1;
      counters.set(ip, rec);
    }
  }
}

// Clear failed-attempt counters after a successful authentication.
export function clearAttempts(store: Store, identifier: string, ip: string): void {
  getCounters(store, bfKey).delete(`${identifier}|${ip}`);
  getCounters(store, bfKey).delete(identifier);
}

// Remove user blocks for an identifier (the user-blocks unblock API).
export function unblock(store: Store, identifier: string): void {
  const as = getAuth0Store(store);
  for (const block of as.userBlocks.findBy("identifier", identifier)) {
    as.userBlocks.delete(block.id);
  }
  getCounters(store, bfKey).delete(identifier);
  // Also clear any "{identifier}|{ip}" composite keys.
  const counters = getCounters(store, bfKey);
  for (const key of [...counters.keys()]) {
    if (key.startsWith(`${identifier}|`)) counters.delete(key);
  }
}

export function clientIp(headerValue: string | undefined): string {
  if (!headerValue) return "127.0.0.1";
  return headerValue.split(",")[0]?.trim() || "127.0.0.1";
}
