"""Metrics for AegisAI decisions.

Uses Redis counters so Grafana can visualize governance activity in real time.

Keys:
  aegis:decisions:total             -> total requests
  aegis:decisions:<action>          -> per-action counters
  aegis:policies:<policy_name>      -> per-policy counters
  aegis:findings:total              -> total findings detected
  aegis:findings:<plugin>           -> per-plugin counters
  aegis:latency_ms                  -> last recorded policy evaluation latency

All keys are incremented atomically. Redis is optional — if it's not
reachable, all functions become no-ops so the gateway never fails because
of observability.
"""

from __future__ import annotations

import os

import redis

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")

_client: redis.Redis | None = None
_disabled = False


def _get_client() -> redis.Redis | None:
    """Lazy-init Redis. Return None if unreachable (metrics are optional)."""
    global _client, _disabled
    if _disabled:
        return None
    if _client is None:
        try:
            _client = redis.Redis.from_url(REDIS_URL, decode_responses=True)
            _client.ping()
        except Exception:
            _disabled = True
            return None
    return _client


def record_decision(action: str, policy_name: str | None, findings_count: int) -> None:
    """Record a decision event."""
    client = _get_client()
    if client is None:
        return
    try:
        pipe = client.pipeline()
        pipe.incr("aegis:decisions:total")
        pipe.incr(f"aegis:decisions:{action}")
        if policy_name:
            pipe.incr(f"aegis:policies:{policy_name}")
        pipe.incr("aegis:findings:total", findings_count)
        pipe.execute()
    except Exception:
        # Never let metrics bring down the gateway.
        pass


def record_finding(plugin: str) -> None:
    """Record a single finding by plugin name."""
    client = _get_client()
    if client is None:
        return
    try:
        client.incr(f"aegis:findings:{plugin}")
    except Exception:
        pass


def record_latency(latency_ms: float) -> None:
    """Record the policy evaluation latency in milliseconds."""
    client = _get_client()
    if client is None:
        return
    try:
        client.set("aegis:latency_ms", latency_ms)
    except Exception:
        pass


def snapshot() -> dict:
    """Return a snapshot of all AegisAI metrics. Used by /metrics endpoint."""
    client = _get_client()
    if client is None:
        return {"redis": "unavailable"}

    try:
        keys = client.keys("aegis:*")
        return {k: client.get(k) for k in keys}
    except Exception:
        return {"redis": "error"}
