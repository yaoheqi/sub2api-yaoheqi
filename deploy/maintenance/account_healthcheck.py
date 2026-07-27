#!/usr/bin/env python3
"""Concurrent OpenAI account probe with ownership-aware scheduling states."""

import base64
import concurrent.futures
import fcntl
import hashlib
import hmac
import json
import os
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


BASE_URL = os.getenv("SUB2API_HEALTH_BASE_URL", "http://127.0.0.1:8080")
REPORT_DIR = Path(os.getenv("SUB2API_HEALTH_REPORT_DIR", "/opt/sub2api/maintenance/reports"))
LOCK_FILE = Path(os.getenv("SUB2API_HEALTH_LOCK_FILE", "/run/sub2api-account-health.lock"))
WORKERS = max(1, int(os.getenv("SUB2API_HEALTH_WORKERS", "8")))
TIMEOUT = max(10, int(os.getenv("SUB2API_HEALTH_TIMEOUT", "90")))
RETRIES = max(1, int(os.getenv("SUB2API_HEALTH_RETRIES", "2")))
RETRY_DELAY = max(1, int(os.getenv("SUB2API_HEALTH_RETRY_DELAY", "8")))
REPORT_RETENTION_DAYS = max(1, int(os.getenv("SUB2API_HEALTH_REPORT_RETENTION_DAYS", "14")))
DRY_RUN = os.getenv("SUB2API_HEALTH_DRY_RUN", "0").lower() in {"1", "true", "yes"}
TEST_MODEL = os.getenv("SUB2API_HEALTH_MODEL", "gpt-5.5")
TEST_PROMPT = os.getenv("SUB2API_HEALTH_PROMPT", "hi")
RATE_LIMIT_FALLBACK_MINUTES = max(1, int(os.getenv("SUB2API_HEALTH_RATE_LIMIT_MINUTES", "30")))
TRANSIENT_COOLDOWN_MINUTES = max(1, int(os.getenv("SUB2API_HEALTH_TRANSIENT_MINUTES", "15")))

OUTCOMES = (
    "success",
    "rate_limited",
    "auth_error",
    "unavailable",
    "unsupported_model",
    "transient_error",
    "other_error",
)
AUTH_PREFIX = "healthcheck authentication failed;"
UNAVAILABLE_PREFIX = "healthcheck unavailable;"
TRANSIENT_PREFIX = "healthcheck transient failure;"


def log(event, **fields):
    print(json.dumps({"time": datetime.now(timezone.utc).isoformat(), "event": event, **fields}, ensure_ascii=True), flush=True)


def run_psql(sql):
    proc = subprocess.run(
        ["docker", "exec", "-i", "sub2api-postgres", "psql", "-X", "-q", "-t", "-A", "-v", "ON_ERROR_STOP=1", "-U", "sub2api", "-d", "sub2api"],
        input=sql,
        text=True,
        capture_output=True,
        timeout=60,
    )
    if proc.returncode:
        raise RuntimeError(proc.stderr.strip() or "psql failed")
    return [line for line in proc.stdout.splitlines() if line.strip()]


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def admin_token():
    rows = run_psql("""
SELECT json_build_object(
  'id', id, 'email', email, 'role', role, 'password_hash', password_hash,
  'jwt_secret', (SELECT value FROM security_secrets WHERE key = 'jwt_secret')
)::text
FROM users
WHERE role = 'admin' AND status = 'active' AND deleted_at IS NULL
ORDER BY totp_enabled ASC, id ASC
LIMIT 1;
""")
    if not rows:
        raise RuntimeError("no active admin user found")
    admin = json.loads(rows[0])
    secret = (admin.get("jwt_secret") or "").strip()
    if not secret:
        raise RuntimeError("persisted JWT secret is missing")
    material = admin["email"].strip().lower() + "\n" + admin["password_hash"]
    token_version = int.from_bytes(hashlib.sha256(material.encode()).digest()[:8], "big") & 0x7FFFFFFFFFFFFFFF
    now = int(time.time())
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "user_id": admin["id"], "email": admin["email"], "role": admin["role"],
        "token_version": token_version, "sid": secrets.token_hex(8),
        "iat": now, "nbf": now, "exp": now + 1800,
    }
    encoded = b64url(json.dumps(header, separators=(",", ":")).encode()) + "." + b64url(json.dumps(payload, separators=(",", ":")).encode())
    signature = hmac.new(secret.encode(), encoded.encode(), hashlib.sha256).digest()
    return encoded + "." + b64url(signature)


def load_accounts():
    rows = run_psql(f"""
SELECT json_build_object(
  'id', id, 'platform', platform, 'type', type,
  'auth_mode', COALESCE(credentials->>'auth_mode', '')
)::text
FROM accounts
WHERE deleted_at IS NULL
  AND parent_account_id IS NULL
  AND platform = 'openai'
  AND (
    (status = 'active' AND schedulable = TRUE)
    OR (status = 'error' AND error_message LIKE '{AUTH_PREFIX}%')
    OR (status = 'active' AND schedulable = FALSE AND error_message LIKE '{UNAVAILABLE_PREFIX}%')
  )
ORDER BY id;
""")
    return [json.loads(row) for row in rows]


def classify_error(error):
    message = (error or "").lower()
    if any(value in message for value in ("api returned 429", "http 429", "too many requests", "rate limit", "usage_limit_reached")):
        return "rate_limited"
    if any(value in message for value in ("api returned 401", "http 401", "api returned 403", "http 403", "unauthorized", "invalid token", "token expired", "token_invalidated", "token_revoked", "failed to build agent identity authentication")):
        return "auth_error"
    if any(value in message for value in ("api returned 402", "http 402", "deactivated_workspace", "deactivated workspace", "workspace disabled", "account deactivated")):
        return "unavailable"
    if any(value in message for value in ("model_not_found", "model is not supported", "not supported by any configured account")):
        return "unsupported_model"
    if any(value in message for value in ("timed out", "timeout", "connection reset", "temporary failure", "remote disconnected", "connection refused")):
        return "transient_error"
    if any(f"api returned {status}" in message or f"http {status}" in message for status in range(500, 600)):
        return "transient_error"
    return "other_error"


def test_once(account, token):
    payload = json.dumps({"model_id": TEST_MODEL, "prompt": TEST_PROMPT}, separators=(",", ":")).encode()
    request = urllib.request.Request(
        f"{BASE_URL}/api/v1/admin/accounts/{account['id']}/test",
        data=payload,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json", "Accept": "text/event-stream"},
        method="POST",
    )
    started = time.monotonic()
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            body = response.read(1024 * 1024).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        body = exc.read(65536).decode("utf-8", errors="replace")
        error = f"HTTP {exc.code}: {body[:1000]}"
        return classify_error(error), error, int((time.monotonic() - started) * 1000)
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
        return classify_error(error), error, int((time.monotonic() - started) * 1000)

    errors = []
    success = False
    for line in body.splitlines():
        if not line.startswith("data:"):
            continue
        try:
            event = json.loads(line.split(":", 1)[1].strip())
        except (ValueError, json.JSONDecodeError):
            continue
        if event.get("type") == "error" and event.get("error"):
            errors.append(str(event["error"]))
        if event.get("type") == "test_complete" and event.get("success") is True:
            success = True
    elapsed = int((time.monotonic() - started) * 1000)
    if success:
        return "success", "", elapsed
    error = "; ".join(errors)[:2000] or "test ended without a success event"
    return classify_error(error), error, elapsed


def test_account(account, token):
    attempts = []
    for attempt in range(1, RETRIES + 1):
        outcome, error, latency_ms = test_once(account, token)
        attempts.append({"attempt": attempt, "outcome": outcome, "error": error, "latency_ms": latency_ms})
        if outcome in {"success", "rate_limited", "auth_error", "unavailable", "unsupported_model"}:
            break
        if attempt < RETRIES:
            time.sleep(RETRY_DELAY)
    return {
        "id": account["id"], "platform": account["platform"], "type": account["type"],
        "auth_mode": account["auth_mode"], "model": TEST_MODEL,
        "outcome": outcome, "ok": outcome == "success", "attempts": attempts,
    }


def sql_id_array(values):
    ids = ",".join(str(int(value)) for value in sorted(set(values)))
    return f"ARRAY[{ids}]::bigint[]" if ids else "ARRAY[]::bigint[]"


def sql_reason(prefix, report_name):
    return f"{prefix} see {report_name}".replace("'", "''")


def apply_results(outcome_ids, report_name):
    if DRY_RUN or not any(outcome_ids.values()):
        return []
    arrays = {key: sql_id_array(outcome_ids[key]) for key in OUTCOMES}
    auth_reason = sql_reason(AUTH_PREFIX, report_name)
    unavailable_reason = sql_reason(UNAVAILABLE_PREFIX, report_name)
    transient_reason = sql_reason(TRANSIENT_PREFIX, report_name)
    rows = run_psql(f"""
BEGIN;
SELECT pg_advisory_xact_lock(hashtext('sub2api_account_healthcheck_update'));
WITH recovered AS (
  UPDATE accounts a
  SET status = 'active', schedulable = TRUE, error_message = '',
      rate_limited_at = NULL, rate_limit_reset_at = NULL,
      overload_until = NULL, temp_unschedulable_until = NULL,
      temp_unschedulable_reason = NULL, updated_at = NOW()
  WHERE a.deleted_at IS NULL
    AND (a.id = ANY({arrays['success']}) OR a.parent_account_id = ANY({arrays['success']}))
  RETURNING a.id
), limited AS (
  UPDATE accounts a
  SET status = 'active', schedulable = TRUE, error_message = '',
      temp_unschedulable_until = NULL, temp_unschedulable_reason = NULL,
      rate_limited_at = NOW(),
      rate_limit_reset_at = GREATEST(COALESCE(a.rate_limit_reset_at, NOW()), NOW() + INTERVAL '{RATE_LIMIT_FALLBACK_MINUTES} minutes'),
      updated_at = NOW()
  WHERE a.deleted_at IS NULL
    AND (a.id = ANY({arrays['rate_limited']}) OR a.parent_account_id = ANY({arrays['rate_limited']}))
  RETURNING a.id
), auth_failed AS (
  UPDATE accounts a
  SET status = 'error', schedulable = FALSE, error_message = '{auth_reason}',
      rate_limited_at = NULL, rate_limit_reset_at = NULL,
      overload_until = NULL, temp_unschedulable_until = NULL,
      temp_unschedulable_reason = NULL, updated_at = NOW()
  WHERE a.deleted_at IS NULL
    AND (a.id = ANY({arrays['auth_error']}) OR a.parent_account_id = ANY({arrays['auth_error']}))
  RETURNING a.id
), unavailable AS (
  UPDATE accounts a
  SET status = 'active', schedulable = FALSE, error_message = '{unavailable_reason}',
      rate_limited_at = NULL, rate_limit_reset_at = NULL,
      overload_until = NULL, temp_unschedulable_until = NULL,
      temp_unschedulable_reason = NULL, updated_at = NOW()
  WHERE a.deleted_at IS NULL
    AND (a.id = ANY({arrays['unavailable']}) OR a.parent_account_id = ANY({arrays['unavailable']}))
  RETURNING a.id
), unsupported AS (
  UPDATE accounts a
  SET temp_unschedulable_until = NULL, temp_unschedulable_reason = NULL,
      updated_at = NOW()
  WHERE a.deleted_at IS NULL
    AND a.temp_unschedulable_reason LIKE '{TRANSIENT_PREFIX}%'
    AND (a.id = ANY({arrays['unsupported_model']}) OR a.parent_account_id = ANY({arrays['unsupported_model']}))
  RETURNING a.id
), transient AS (
  UPDATE accounts a
  SET status = 'active', schedulable = TRUE,
      temp_unschedulable_until = GREATEST(COALESCE(a.temp_unschedulable_until, NOW()), NOW() + INTERVAL '{TRANSIENT_COOLDOWN_MINUTES} minutes'),
      temp_unschedulable_reason = '{transient_reason}', updated_at = NOW()
  WHERE a.deleted_at IS NULL
    AND (a.id = ANY({arrays['transient_error']})
      OR a.id = ANY({arrays['other_error']})
      OR a.parent_account_id = ANY({arrays['transient_error']})
      OR a.parent_account_id = ANY({arrays['other_error']}))
  RETURNING a.id
), updated AS (
  SELECT id FROM recovered UNION ALL SELECT id FROM limited
  UNION ALL SELECT id FROM auth_failed UNION ALL SELECT id FROM unavailable
  UNION ALL SELECT id FROM unsupported UNION ALL SELECT id FROM transient
), event AS (
  INSERT INTO scheduler_outbox (event_type, account_id, group_id, payload)
  SELECT 'account_bulk_changed', NULL, NULL,
         jsonb_build_object('account_ids', COALESCE(jsonb_agg(id ORDER BY id), '[]'::jsonb))
  FROM updated HAVING COUNT(*) > 0 RETURNING id
)
SELECT id FROM updated ORDER BY id;
COMMIT;
""")
    return [int(row) for row in rows if row.isdigit()]


def prune_reports():
    cutoff = time.time() - REPORT_RETENTION_DAYS * 86400
    for path in REPORT_DIR.glob("healthcheck-*.json"):
        try:
            if path.stat().st_mtime < cutoff:
                path.unlink()
        except FileNotFoundError:
            pass


def main():
    LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
    with LOCK_FILE.open("w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            log("skipped", reason="another healthcheck is running")
            return 0
        started = datetime.now(timezone.utc)
        accounts = load_accounts()
        token = admin_token()
        log("scan_started", accounts=len(accounts), workers=WORKERS, retries=RETRIES, model=TEST_MODEL, prompt=TEST_PROMPT, dry_run=DRY_RUN)
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as executor:
            futures = {executor.submit(test_account, account, token): account["id"] for account in accounts}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                results.append(result)
                log("account_tested", account_id=result["id"], outcome=result["outcome"], attempts=len(result["attempts"]), model=result["model"])
        results.sort(key=lambda item: item["id"])
        outcome_ids = {outcome: [item["id"] for item in results if item["outcome"] == outcome] for outcome in OUTCOMES}
        stamp = started.strftime("%Y%m%dT%H%M%SZ")
        REPORT_DIR.mkdir(parents=True, exist_ok=True)
        report_path = REPORT_DIR / f"healthcheck-{stamp}.json"
        report = {
            "started_at": started.isoformat(), "finished_at": datetime.now(timezone.utc).isoformat(),
            "dry_run": DRY_RUN, "tested": len(results), "model": TEST_MODEL, "prompt": TEST_PROMPT,
            "outcomes": {key: len(value) for key, value in outcome_ids.items()}, "results": results,
        }
        encoded = json.dumps(report, indent=2, ensure_ascii=True) + "\n"
        report_path.write_text(encoded, encoding="utf-8")
        temp = REPORT_DIR / ".latest.json.tmp"
        temp.write_text(encoded, encoding="utf-8")
        temp.replace(REPORT_DIR / "latest.json")
        prune_reports()
        updated_ids = apply_results(outcome_ids, str(report_path))
        log("scan_finished", tested=len(results), outcomes={key: len(value) for key, value in outcome_ids.items()}, updated=len(updated_ids), report=str(report_path))
        return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        log("fatal", error=f"{type(exc).__name__}: {exc}")
        raise
