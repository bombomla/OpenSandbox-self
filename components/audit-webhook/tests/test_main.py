# Copyright 2026 Alibaba Group Holding Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Tests for the audit webhook API.

Uses a fake store so no PostgreSQL instance is required.
"""

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.error import HTTPError

import pytest
from fastapi.testclient import TestClient

# Tests live in tests/; the webhook sources are one level up (main.py,
# store.py) with helpers in utils/.
_ROOT = Path(__file__).resolve().parent.parent
for _path in (str(_ROOT), str(_ROOT / "utils")):
    if _path not in sys.path:
        sys.path.insert(0, _path)

import main
from store import _normalize, _normalize_alert


class FakeStore:
    def __init__(self):
        self.events = []
        self.alerts = []
        self.fail = False
        self.deleted_ids = set()
        self.unaccessed = {}  # sandbox_id -> created_at
        # created_at per known row (event rows start as None); mimics the
        # backfill in upsert_discovered_sandboxes.
        self.created_at = {}
        self.node_ips = {}  # sandbox_id -> node IP
        self.user_ids = {}  # sandbox_id -> user id
        # Toggle to make only the stale-user lookup fail (ingestion stays
        # up, mirroring the route's error isolation).
        self.stale_fail = False
        # Every list_stale_users call: (node_ip, stale_days, exclude_users).
        self.stale_queries = []

    def init_schema(self):
        pass

    def record(self, events):
        if self.fail:
            raise RuntimeError("db down")
        self.events.extend(_normalize(event) for event in events)
        # Mimic the upsert: a first request flips the row to accessed.
        for event in events:
            self.created_at.setdefault(event["sandbox_id"], None)
            self.unaccessed.pop(event["sandbox_id"], None)
        return len(events)

    def record_alerts(self, alerts):
        # Mirrors AuditStore.record_alerts: append-only, one row per
        # delivered alert, normalized like the SQL write path.
        if self.fail:
            raise RuntimeError("db down")
        for alert in alerts:
            row = _normalize_alert(alert)
            row["id"] = len(self.alerts) + 1  # BIGSERIAL
            row["received_at"] = row["starts_at"]  # DB default now()
            self.alerts.append(row)
        return len(alerts)

    def list_alerts(self, status=None, search=None, limit=50, offset=0):
        if self.fail:
            raise RuntimeError("db down")

        def matches(alert):
            if status is not None and alert["status"] != status:
                return False
            if search is not None:
                # Mirrors the SQL: ILIKE across fingerprint, receiver,
                # group_key and the JSON text of labels/annotations.
                haystack = " ".join(
                    [
                        alert["fingerprint"],
                        alert["receiver"] or "",
                        alert["group_key"] or "",
                        json.dumps(alert["labels"], ensure_ascii=False),
                        json.dumps(alert["annotations"], ensure_ascii=False),
                    ]
                )
                if search.lower() not in haystack.lower():
                    return False
            return True

        items = sorted(
            (alert for alert in self.alerts if matches(alert)),
            key=lambda alert: alert["id"],
            reverse=True,
        )
        return {"total": len(items), "items": items[offset : offset + limit]}

    def upsert_discovered_sandboxes(self, sandboxes):
        if self.fail:
            raise RuntimeError("db down")
        discovered = [
            sandbox
            for sandbox in sandboxes
            if sandbox["name"] not in self.created_at
        ]
        backfilled = [
            sandbox
            for sandbox in sandboxes
            if sandbox["name"] in self.created_at
            and self.created_at[sandbox["name"]] is None
            and sandbox.get("created_at") is not None
        ]
        user_backfilled = [
            sandbox
            for sandbox in sandboxes
            if sandbox["name"] in self.user_ids
            and self.user_ids[sandbox["name"]] is None
            and sandbox.get("user_id") is not None
        ]
        for sandbox in discovered:
            self.created_at[sandbox["name"]] = sandbox.get("created_at")
            self.unaccessed[sandbox["name"]] = sandbox.get("created_at")
        for sandbox in backfilled:
            self.created_at[sandbox["name"]] = sandbox["created_at"]
        for sandbox in sandboxes:
            if sandbox.get("user_id") is not None:
                self.user_ids.setdefault(sandbox["name"], sandbox["user_id"])
        return {
            "discovered": len(discovered),
            "backfilled": len(backfilled) + len(user_backfilled),
        }

    def update_node_ips(self, nodes):
        if self.fail:
            raise RuntimeError("db down")
        known = set(self.created_at) | set(self.unaccessed)
        changed = [
            sandbox_id
            for sandbox_id, ip in nodes.items()
            if sandbox_id in known and self.node_ips.get(sandbox_id) != ip
        ]
        for sandbox_id in changed:
            self.node_ips[sandbox_id] = nodes[sandbox_id]
        return len(changed)

    def _user_of(self, sandbox_id):
        # uid = user_id when known, else the bare sandbox id.
        return self.user_ids.get(sandbox_id, sandbox_id)

    def is_deleted(self, sandbox_id):
        return sandbox_id in self.deleted_ids

    def list_latest(
        self,
        search=None,
        sort="-request_time",
        limit=50,
        offset=0,
        time_from=None,
        time_to=None,
        whitelist_users=None,
        user_type=None,
    ):
        if self.fail:
            raise RuntimeError("db down")
        whitelist = set(whitelist_users or [])

        def matches_search(sandbox_id):
            if search is None:
                return True
            # Mimic the SQL: fuzzy on user id/sandbox id (any member) OR
            # exact on node_ip.
            uid = self._user_of(sandbox_id)
            return (
                search.lower() in uid.lower()
                or search.lower() in sandbox_id.lower()
                or self.node_ips.get(sandbox_id) == search
            )

        def member_row(sandbox_id: str, request_time) -> dict:
            unaccessed = request_time is None
            return {
                "sandbox_id": sandbox_id,
                "request_time": request_time,
                "request_count": 0 if unaccessed else 1,
                "accessed": not unaccessed,
                "created_at": self.created_at.get(sandbox_id),
                "node_ip": self.node_ips.get(sandbox_id),
                "user_id": self.user_ids.get(sandbox_id),
            }

        # Latest request per sandbox (mimics the summary row's
        # request_time); time filters no longer drop members - they bind
        # the group's effective request time below.
        latest: dict[str, object] = {}
        for event in self.events:
            sandbox_id = event["sandbox_id"]
            if sandbox_id not in latest or event["request_time"] > latest[sandbox_id]:
                latest[sandbox_id] = event["request_time"]
        seen: set[str] = set()
        members: list[dict] = []
        for sandbox_id, request_time in latest.items():
            if self.is_deleted(sandbox_id) or not matches_search(sandbox_id):
                continue
            members.append(member_row(sandbox_id, request_time))
            seen.add(sandbox_id)
        # Discovered-but-never-accessed rows: NULL request fields, count 0.
        for sandbox_id, _created_at in self.unaccessed.items():
            if (
                sandbox_id in seen
                or self.is_deleted(sandbox_id)
                or not matches_search(sandbox_id)
            ):
                continue
            members.append(member_row(sandbox_id, None))
            seen.add(sandbox_id)
        # Group by user: uid = user_id when known, else the sandbox id.
        # Member request_count sums every recorded event (SUM over rows).
        counts: dict[str, int] = {}
        for event in self.events:
            sb = event["sandbox_id"]
            if not self.is_deleted(sb):
                counts[sb] = counts.get(sb, 0) + 1
        groups: dict[str, dict] = {}
        for m in members:
            uid = self._user_of(m["sandbox_id"])
            group = groups.setdefault(
                uid,
                {
                    "uid": uid,
                    "user_id": m["user_id"],
                    "sandbox_id": m["sandbox_id"],
                    "node_ip": m["node_ip"],
                    "sandbox_count": 0,
                    "accessed": True,
                    "created_at": None,
                    "request_time": None,
                    "request_count": 0,
                },
            )
            group["sandbox_count"] += 1
            group["accessed"] = group["accessed"] and m["accessed"]
            if m["created_at"] and (
                group["created_at"] is None or m["created_at"] < group["created_at"]
            ):
                group["created_at"] = m["created_at"]
            if m["request_time"] and (
                group["request_time"] is None or m["request_time"] > group["request_time"]
            ):
                group["request_time"] = m["request_time"]
            group["request_count"] += counts.get(m["sandbox_id"], 0)
        # Fallback (SQL: the per-uid window max over ALL rows, deleted
        # included): a group whose current sandbox was never accessed
        # reports the user's latest request from their deleted sandboxes.
        history: dict[str, object] = {}
        for event in self.events:
            uid = self._user_of(event["sandbox_id"])
            if uid not in history or event["request_time"] > history[uid]:
                history[uid] = event["request_time"]
        for group in groups.values():
            if group["request_time"] is None:
                group["request_time"] = history.get(group["uid"])
        items = list(groups.values())
        # Time filters bind the effective (post-fallback) group request
        # time; a group without any time falls out (NULL comparisons are
        # not TRUE in SQL).
        if time_from is not None:
            items = [
                item
                for item in items
                if item["request_time"] is not None
                and item["request_time"] >= time_from
            ]
        if time_to is not None:
            items = [
                item
                for item in items
                if item["request_time"] is not None
                and item["request_time"] <= time_to
            ]
        # Whitelist (VIP) type filter, mirroring the SQL on the group key.
        if user_type == "vip":
            items = [item for item in items if item["uid"] in whitelist]
        elif user_type == "normal":
            items = [item for item in items if item["uid"] not in whitelist]
        return {
            "total": len(items),
            "items": items[offset : offset + limit],
            "sort": sort,
            "search": search,
        }

    def list_host_sandboxes(self, node_ip, stale_days=None):
        # Mirrors AuditStore.list_host_sandboxes: live (non-deleted) rows
        # on the node, one row per sandbox with user_id, created_at and
        # request_time (NULL when never accessed). stale_days keeps only
        # rows whose effective last-active time (request_time, else
        # created_at) is older than that many days; a row with no
        # timestamp at all counts as stale. Least-recently-active first.
        if self.fail:
            raise RuntimeError("db down")
        cutoff = (
            datetime.now(timezone.utc) - timedelta(days=stale_days)
            if stale_days is not None
            else None
        )
        latest = {}
        for event in self.events:
            sb = event["sandbox_id"]
            if sb not in latest or event["request_time"] > latest[sb]:
                latest[sb] = event["request_time"]
        _floor = datetime.min.replace(tzinfo=timezone.utc)
        items = []
        for sandbox_id in self.created_at:
            if self.is_deleted(sandbox_id):
                continue
            if self.node_ips.get(sandbox_id) != node_ip:
                continue
            request_time = latest.get(sandbox_id)
            created_at = self.created_at.get(sandbox_id)
            last_active = request_time or created_at
            if cutoff is not None:
                if last_active is not None and last_active >= cutoff:
                    continue
                # last_active None -> stale (no timestamp at all).
            items.append(
                {
                    "sandbox_id": sandbox_id,
                    "user_id": self.user_ids.get(sandbox_id),
                    "created_at": created_at,
                    "request_time": request_time,
                }
            )
        # ORDER BY COALESCE(request_time, created_at) ASC NULLS FIRST.
        items.sort(key=lambda item: (item["request_time"] or item["created_at"]) or _floor)
        return {"total": len(items), "items": items}

    def list_details(self, sandbox_id=None, user_id=None, limit=50, offset=0):
        if self.fail:
            raise RuntimeError("db down")
        if user_id is not None:
            # History: all of the user's sandboxes, deleted ones included.
            member_ids = {
                sb for sb, uid in self.user_ids.items() if uid == user_id
            }
            matches = [
                event
                for event in self.events
                if event["sandbox_id"] in member_ids
            ]
        else:
            matches = [
                event
                for event in self.events
                if sandbox_id is None or event["sandbox_id"] == sandbox_id
            ]
        items = [
            {
                "id": index + 1,
                "received_at": event["request_time"],
                "user_id": self.user_ids.get(event["sandbox_id"]),
                "sandbox_deleted": event["sandbox_id"] in self.deleted_ids,
                **event,
            }
            for index, event in enumerate(matches[offset : offset + limit])
        ]
        return {"total": len(matches), "items": items}

    def list_sandbox_times(self, limit=50, offset=0, exclude_users=None):
        if self.fail:
            raise RuntimeError("db down")
        excluded = set(exclude_users or [])
        # Latest request time per sandbox (None = never accessed).
        latest = {}
        for event in self.events:
            sandbox_id = event["sandbox_id"]
            if sandbox_id not in latest or event["request_time"] > latest[sandbox_id]:
                latest[sandbox_id] = event["request_time"]
        items = [
            {
                "sandbox_id": sandbox_id,
                "user_id": self.user_ids.get(sandbox_id),
                "created_at": self.created_at.get(sandbox_id),
                # COALESCE(request_time, created_at): never-accessed rows
                # report the creation time as their latest request time.
                "request_time": latest.get(sandbox_id, self.created_at.get(sandbox_id)),
            }
            for sandbox_id in self.created_at
            # Whitelisted users are excluded; rows without a user id stay.
            if self.user_ids.get(sandbox_id) not in excluded
        ]

        def sort_key(item):
            time = item["request_time"]
            # DESC NULLS LAST: rows without any time go to the end.
            return (time is None, time)

        items.sort(key=sort_key, reverse=True)
        return {"total": len(items), "items": items[offset : offset + limit]}

    def sync_deleted_flags(self, live_ids):
        if self.fail:
            raise RuntimeError("db down")
        live = set(live_ids)
        all_ids = {event["sandbox_id"] for event in self.events}
        prev_deleted = getattr(self, "deleted_ids", set())
        # Mimic the SQL: only rows whose flag actually changes are counted.
        deleted = (all_ids - prev_deleted) - live
        restored = prev_deleted & live
        self.deleted_ids = (prev_deleted | all_ids) - live
        return {"deleted": len(deleted), "restored": len(restored)}

    def list_stale_users(self, node_ip, stale_days=7, exclude_users=None):
        # Mirrors AuditStore.list_stale_users: live rows on the node with
        # a user id, one group per user. The group's effective last access
        # is its current sandbox's latest request, or - when it was never
        # accessed - the user's latest request across all their rows
        # (deleted sandboxes included), or the sandbox's creation time. A
        # group without any timestamp counts as stale; a group older than
        # the cutoff (stale_days) is stale. VIP users drop out.
        if self.stale_fail:
            raise RuntimeError("db down")
        self.stale_queries.append((node_ip, stale_days, list(exclude_users or [])))
        excluded = set(exclude_users or [])
        cutoff = datetime.now(timezone.utc) - timedelta(days=stale_days)
        # Latest request per sandbox (the summary row's request_time).
        latest = {}
        for event in self.events:
            sandbox_id = event["sandbox_id"]
            if sandbox_id not in latest or event["request_time"] > latest[sandbox_id]:
                latest[sandbox_id] = event["request_time"]
        # Live member rows on the node with a resolved user id.
        members = [
            sandbox_id
            for sandbox_id in self.created_at
            if not self.is_deleted(sandbox_id)
            and self.node_ips.get(sandbox_id) == node_ip
            and self.user_ids.get(sandbox_id) is not None
            and self.user_ids[sandbox_id] not in excluded
        ]
        # The user's latest request across ALL rows, deleted included
        # (mirrors the all_rows window).
        history = {}
        for event in self.events:
            uid = self._user_of(event["sandbox_id"])
            if uid not in history or event["request_time"] > history[uid]:
                history[uid] = event["request_time"]
        groups = {}
        for sandbox_id in members:
            uid = self.user_ids[sandbox_id]
            group = groups.setdefault(
                uid,
                {"user_id": uid, "sandbox_id": None, "request": None, "created": None},
            )
            if group["sandbox_id"] is None or sandbox_id > group["sandbox_id"]:
                group["sandbox_id"] = sandbox_id
            request_time = latest.get(sandbox_id)
            if request_time is not None and (
                group["request"] is None or request_time > group["request"]
            ):
                group["request"] = request_time
            created_at = self.created_at.get(sandbox_id)
            if created_at is not None and (
                group["created"] is None or created_at < group["created"]
            ):
                group["created"] = created_at
        items = []
        for group in groups.values():
            # COALESCE(max(request_time), history, min(created_at)); a
            # group without any timestamp at all counts as stale.
            last = group["request"] or history.get(group["user_id"]) or group["created"]
            if last is not None and last >= cutoff:
                continue
            items.append(
                {
                    "user_id": group["user_id"],
                    "sandbox_id": group["sandbox_id"],
                    "last_access": (
                        last.replace(microsecond=0).isoformat()
                        if last is not None
                        else None
                    ),
                }
            )
        # ORDER BY last_access ASC NULLS FIRST
        items.sort(
            key=lambda item: (item["last_access"] is not None, item["last_access"])
        )
        return items


@pytest.fixture()
def client(monkeypatch):
    fake = FakeStore()
    # Force auth off and the whitelist empty regardless of the local
    # audit.toml so tests are independent of the developer's
    # configuration (auth/whitelist-specific tests override these via
    # monkeypatch themselves).
    monkeypatch.setattr(main, "UI_PASSWORD", "")
    monkeypatch.setattr(main, "WHITELIST_USERS", [])
    monkeypatch.setattr(main, "ALERT_AUTH_TOKEN", "")
    # Memory-alert stale-user lookup is off by default (empty alertname
    # list); tests that exercise it override MEMORY_ALERT_NAMES.
    monkeypatch.setattr(main, "MEMORY_ALERT_NAMES", [])
    monkeypatch.setattr(main, "STALE_DAYS", 7)
    # Auto-stop is off by default; stop-calling tests override these.
    monkeypatch.setattr(main, "STOP_SANDBOXES", False)
    monkeypatch.setattr(main, "STOP_URL", "")
    monkeypatch.setattr(main, "STOP_SLUG", "")
    monkeypatch.setattr(main, "STOP_LIMIT", 10)
    # Bypass the lifespan (which opens a real PostgreSQL pool) by injecting
    # the fake store directly into app state.
    main.app.state.store = fake
    test_client = TestClient(main.app)
    yield test_client, fake
    main.app.state.store = None


EVENT = {
    "sandbox_id": "test-sandbox",
    "uri": "/api/users",
    "method": "GET",
    "target": "10.0.0.1:8080",
    "request_time": "2026-08-20T09:24:12.252+08:00",
}

# A full Alertmanager webhook notification (version 4, camelCase as
# Alertmanager sends it). startsAt carries Alertmanager's nanosecond
# precision; endsAt "0001-01-01T00:00:00Z" means "still firing".
ALERTMANAGER_PAYLOAD = {
    "version": "4",
    "groupKey": '{}:{"alertname":"HighMemory"}',
    "truncatedAlerts": 0,
    "status": "firing",
    "receiver": "audit-webhook",
    "groupLabels": {"alertname": "HighMemory"},
    "commonLabels": {"alertname": "HighMemory", "severity": "warning"},
    "commonAnnotations": {"summary": "内存使用过高"},
    "externalURL": "http://alertmanager:9093",
    "alerts": [
        {
            "status": "firing",
            "labels": {
                "alertname": "HighMemory",
                "instance": "pod-1",
                "severity": "warning",
            },
            "annotations": {"summary": "内存使用过高"},
            "startsAt": "2026-09-24T08:00:00.123456789Z",
            "endsAt": "0001-01-01T00:00:00Z",
            "generatorURL": "http://prometheus:9090/graph",
            "fingerprint": "abc123",
        },
        {
            "status": "resolved",
            "labels": {"alertname": "HighCPU", "instance": "pod-2"},
            "annotations": {},
            "startsAt": "2026-09-23T08:00:00Z",
            "endsAt": "2026-09-24T09:00:00Z",
            "generatorURL": "http://prometheus:9090/graph",
            "fingerprint": "def456",
        },
    ],
}


def test_record_single_event(client):
    test_client, fake = client

    response = test_client.post("/events", json=EVENT)

    assert response.status_code == 200
    assert response.json() == {"accepted": 1}
    assert len(fake.events) == 1
    assert fake.events[0]["sandbox_id"] == "test-sandbox"
    # Timestamps are normalized (UTC-assumed if naive, truncated to seconds).
    assert fake.events[0]["request_time"].isoformat() == "2026-08-20T09:24:12+08:00"


def test_record_event_batch(client):
    test_client, fake = client

    response = test_client.post("/events", json=[EVENT, {**EVENT, "sandbox_id": "other"}])

    assert response.status_code == 200
    assert response.json() == {"accepted": 2}
    assert len(fake.events) == 2


def test_record_event_at_root_alias(client):
    """POST / is accepted as an alias for POST /events (path-less webhook URLs)."""
    test_client, fake = client

    response = test_client.post("/", json=EVENT)

    assert response.status_code == 200
    assert response.json() == {"accepted": 1}
    assert len(fake.events) == 1


def test_ping_requests_not_recorded(client):
    """Requests whose URI ends with 'ping' (case-insensitive) are dropped."""
    test_client, fake = client

    # Single ping event: accepted as 0, nothing stored.
    response = test_client.post(
        "/events",
        json={**EVENT, "uri": "/610c205a-272e-425f-85bf-b27cae2d9ee3/44772/ping"},
    )
    assert response.status_code == 200
    assert response.json() == {"accepted": 0}
    assert fake.events == []

    # Mixed batch: only URIs not ending with 'ping' are recorded; 'ping'
    # elsewhere in the URI (not at the end) is kept.
    response = test_client.post(
        "/events",
        json=[
            EVENT,
            {**EVENT, "uri": "/some-sandbox/8080/PING"},
            {**EVENT, "uri": "/api/users?watch=ping&since=1"},
        ],
    )
    assert response.status_code == 200
    assert response.json() == {"accepted": 2}
    assert all(
        not event["uri"].lower().endswith("ping") for event in fake.events
    )
    assert any(
        event["uri"] == "/api/users?watch=ping&since=1" for event in fake.events
    )


def test_query_values_ignored_in_exclusion(monkeypatch):
    """Query-string values are not matched: /usage?days= covers days=<any>.

    The default suffix list is ping-only, so the test pins its own list
    (audit.toml's real list varies per developer).
    """
    from main import _should_record, AuditEvent

    def event(uri):
        return AuditEvent(
            sandbox_id="sb", uri=uri, method="GET", target="t",
            request_time="2026-09-07T00:00:00Z",
        )

    with monkeypatch.context() as m:
        m.setattr("main._EXCLUDED_URI_SUFFIXES", ("/usage?days=",))
        # Any days value is excluded - the value is ignored during matching.
        assert not _should_record(event("/sb/9119/usage?days=1"))
        assert not _should_record(event("/sb/9119/usage?days=2"))
        assert not _should_record(event("/sb/9119/usage?days=30"))
        assert not _should_record(event("/sb/9119/usage?days"))
        # Extra params after it: the value-less name still ends the URI.
        assert not _should_record(event("/sb/9119/usage?days=1&fmt=json"))
        # Different query name is recorded.
        assert _should_record(event("/sb/9119/usage?since=1"))
        # Path-only suffixes keep matching.
        m.setattr("main._EXCLUDED_URI_SUFFIXES", ("ping",))
        assert not _should_record(event("/sb/9119/ping"))
        assert not _should_record(event("/sb/9119/ping?x=1"))
        assert _should_record(event("/sb/9119/pong?x=1"))


def test_reject_invalid_event(client):
    test_client, fake = client

    missing_field = {k: v for k, v in EVENT.items() if k != "target"}
    response = test_client.post("/events", json=missing_field)

    assert response.status_code == 422
    assert fake.events == []


def test_store_failure_returns_502(client):
    test_client, fake = client
    fake.fail = True

    response = test_client.post("/events", json=EVENT)

    assert response.status_code == 502


def test_healthz(client):
    test_client, _ = client

    response = test_client.get("/status.ok")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_sandbox_times_bearer_auth(monkeypatch, client):
    """/api/sandboxes/times accepts an Authorization: Bearer <password>
    header in addition to the session cookie."""
    monkeypatch.setattr(main, "UI_PASSWORD", "secret")
    test_client, fake = client
    fake.record([EVENT])

    # No credentials -> 401.
    response = test_client.get("/api/sandboxes/times")
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"

    # Wrong password -> 401.
    response = test_client.get(
        "/api/sandboxes/times", headers={"Authorization": "Bearer wrong"}
    )
    assert response.status_code == 401

    # Correct password in the header -> 200.
    response = test_client.get(
        "/api/sandboxes/times", headers={"Authorization": "Bearer secret"}
    )
    assert response.status_code == 200
    assert response.json()["total"] == 1

    # A valid session cookie still works.
    test_client.post("/login", json={"password": "secret"})
    response = test_client.get("/api/sandboxes/times")
    assert response.status_code == 200


def test_index_page(client):
    test_client, _ = client

    response = test_client.get("/")

    assert response.status_code == 200
    assert "html" in response.headers["content-type"]
    # The page is a React app built from frontend/; the title lives in the
    # built HTML shell and the table renders client-side.
    assert "沙箱最新请求" in response.text
    assert "/static/assets/" in response.text


def test_details_page(client):
    test_client, _ = client

    response = test_client.get("/details")

    assert response.status_code == 200
    assert "html" in response.headers["content-type"]
    assert "请求详情" in response.text


def test_login_page(client):
    test_client, _ = client

    response = test_client.get("/login")

    assert response.status_code == 200
    assert "html" in response.headers["content-type"]
    assert "密码" in response.text


def test_auth_flow(monkeypatch, client):
    """When AUDIT_UI_PASSWORD is set, pages/APIs require login; events stay open."""
    monkeypatch.setattr(main, "UI_PASSWORD", "secret")
    test_client, _ = client

    # Pages redirect to /login without a session.
    for path in ("/", "/details"):
        response = test_client.get(path, follow_redirects=False)
        assert response.status_code == 303
        assert response.headers["location"] == "/login"

    # APIs reject with 401.
    assert test_client.get("/api/sandboxes").status_code == 401
    assert test_client.get("/api/requests").status_code == 401
    assert test_client.get("/api/whitelist").status_code == 401

    # Event ingestion is never password protected.
    assert test_client.post("/events", json=EVENT).status_code == 200

    # Wrong password is rejected.
    assert test_client.post("/login", json={"password": "wrong"}).status_code == 401

    # Correct password issues a session cookie and unlocks pages/APIs.
    response = test_client.post("/login", json={"password": "secret"})
    assert response.status_code == 200
    assert test_client.get("/", follow_redirects=False).status_code == 200
    assert test_client.get("/details", follow_redirects=False).status_code == 200
    assert test_client.get("/api/sandboxes").status_code == 200
    assert test_client.get("/api/requests").status_code == 200

    # Logout invalidates the session.
    assert test_client.post("/logout").status_code == 200
    assert test_client.get("/api/sandboxes").status_code == 401


def test_auth_disabled_by_default(client):
    """Without AUDIT_UI_PASSWORD, pages/APIs are open and login is a no-op."""
    test_client, _ = client

    assert test_client.get("/", follow_redirects=False).status_code == 200
    assert test_client.get("/api/sandboxes").status_code == 200
    assert test_client.post("/login", json={"password": "anything"}).status_code == 200


def test_get_whitelist(monkeypatch, client):
    """/api/whitelist returns the configured whitelisted user ids."""
    monkeypatch.setattr(main, "WHITELIST_USERS", ["u-1", "u-2"])
    test_client, _ = client

    response = test_client.get("/api/whitelist")

    assert response.status_code == 200
    assert response.json() == {"users": ["u-1", "u-2"]}


def test_get_whitelist_empty(monkeypatch, client):
    """An empty whitelist renders as an empty users list."""
    monkeypatch.setattr(main, "WHITELIST_USERS", [])
    test_client, _ = client

    response = test_client.get("/api/whitelist")

    assert response.status_code == 200
    assert response.json() == {"users": []}


def test_list_sandboxes(client):
    """Without user ids, each sandbox is its own summary group."""
    test_client, fake = client
    fake.record([EVENT, {**EVENT, "sandbox_id": "other"}])

    response = test_client.get("/api/sandboxes")

    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 2
    assert len(data["items"]) == 2
    by_uid = {item["uid"]: item for item in data["items"]}
    assert by_uid["test-sandbox"]["user_id"] is None
    assert by_uid["test-sandbox"]["request_count"] == 1
    assert by_uid["test-sandbox"]["sandbox_count"] == 1


def test_list_sandboxes_fuzzy_search(client):
    test_client, fake = client
    fake.record([EVENT, {**EVENT, "sandbox_id": "other-sandbox"}])

    response = test_client.get("/api/sandboxes", params={"search": "TEST"})

    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 1
    assert data["items"][0]["uid"] == "test-sandbox"


def test_list_sandboxes_sort(client):
    test_client, _ = client

    # Ascending order is passed through.
    response = test_client.get("/api/sandboxes", params={"sort": "request_time"})
    assert response.status_code == 200
    assert response.json()["sort"] == "request_time"

    # Sort by request_count (descending) is allowed.
    response = test_client.get("/api/sandboxes", params={"sort": "-request_count"})
    assert response.status_code == 200
    assert response.json()["sort"] == "-request_count"

    # Sort by accessed (ascending = never-accessed first) is allowed.
    response = test_client.get("/api/sandboxes", params={"sort": "accessed"})
    assert response.status_code == 200
    assert response.json()["sort"] == "accessed"

    # Sort by created_at (sandbox creation timestamp) is allowed.
    response = test_client.get("/api/sandboxes", params={"sort": "-created_at"})
    assert response.status_code == 200
    assert response.json()["sort"] == "-created_at"

    # Unknown sort keys are rejected.
    response = test_client.get("/api/sandboxes", params={"sort": "sandbox_id"})
    assert response.status_code == 422


def test_list_sandboxes_time_range_filter(client):
    """time_from/time_to filter sandboxes by latest request time."""
    test_client, fake = client
    # EVENT's request_time is 2026-08-20T09:24:12+08:00 (= 01:24:12 UTC).
    fake.record([
        EVENT,
        {**EVENT, "sandbox_id": "older", "request_time": "2026-08-10T09:24:12.252+08:00"},
        {**EVENT, "sandbox_id": "newer", "request_time": "2026-08-21T09:24:12.252+08:00"},
    ])

    # Only sandboxes whose latest request falls in the range are returned.
    response = test_client.get(
        "/api/sandboxes",
        params={"time_from": "2026-08-20T00:00:00Z", "time_to": "2026-08-20T23:59:59Z"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 1
    assert data["items"][0]["uid"] == "test-sandbox"

    # The bounds are inclusive and can be used alone.
    response = test_client.get(
        "/api/sandboxes", params={"time_from": "2026-08-21T01:24:12Z"}
    )
    assert response.json()["total"] == 1
    assert response.json()["items"][0]["uid"] == "newer"


def test_list_sandboxes_groups_by_user(client):
    """Sandboxes sharing a user_id roll into one summed group."""
    test_client, fake = client
    # Two sandboxes for user u-1, one bare sandbox without a user id.
    fake.user_ids = {"sb-a": "u-1", "sb-b": "u-1"}
    fake.record([EVENT | {"sandbox_id": "sb-a"},
                 EVENT | {"sandbox_id": "sb-b"}])
    fake.record([{**EVENT, "sandbox_id": "sb-c"}])
    fake.record([{**EVENT, "sandbox_id": "sb-a"}])

    response = test_client.get("/api/sandboxes")

    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 2
    groups = {item["uid"]: item for item in data["items"]}
    user_group = groups["u-1"]
    assert user_group["user_id"] == "u-1"
    assert user_group["sandbox_count"] == 2
    # Summed across both sandboxes, including the repeat event.
    assert user_group["request_count"] == 3
    bare = groups["sb-c"]
    assert bare["user_id"] is None
    assert bare["request_count"] == 1

    # Searching by member sandbox id finds the user group.
    response = test_client.get("/api/sandboxes", params={"search": "sb-b"})
    assert response.json()["total"] == 1
    assert response.json()["items"][0]["uid"] == "u-1"


def test_list_sandboxes_user_type_filter(monkeypatch, client):
    """user_type=vip keeps whitelisted groups; normal keeps the rest."""
    monkeypatch.setattr(main, "WHITELIST_USERS", ["u-1"])
    test_client, fake = client
    fake.user_ids = {"sb-a": "u-1", "sb-b": "u-2"}
    fake.record([EVENT | {"sandbox_id": "sb-a"},
                 EVENT | {"sandbox_id": "sb-b"}])

    # vip -> only u-1's group.
    response = test_client.get("/api/sandboxes", params={"user_type": "vip"})
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 1
    assert data["items"][0]["uid"] == "u-1"

    # normal -> only u-2's group.
    response = test_client.get("/api/sandboxes", params={"user_type": "normal"})
    assert data["total"] == 1 or response.json()["total"] == 1
    assert response.json()["total"] == 1
    assert response.json()["items"][0]["uid"] == "u-2"

    # no filter -> both groups.
    response = test_client.get("/api/sandboxes")
    assert response.json()["total"] == 2


def test_list_sandboxes_user_type_filter_empty_whitelist(monkeypatch, client):
    """An empty whitelist makes every group normal; vip returns none."""
    monkeypatch.setattr(main, "WHITELIST_USERS", [])
    test_client, fake = client
    fake.record([EVENT, {**EVENT, "sandbox_id": "other"}])

    assert test_client.get(
        "/api/sandboxes", params={"user_type": "vip"}
    ).json()["total"] == 0
    assert test_client.get(
        "/api/sandboxes", params={"user_type": "normal"}
    ).json()["total"] == 2


def test_list_sandboxes_sort_user_type(monkeypatch, client):
    """sort=±user_type is accepted; descending puts VIP users first."""
    monkeypatch.setattr(main, "WHITELIST_USERS", ["u-vip"])
    test_client, fake = client
    fake.user_ids = {"sb-vip": "u-vip", "sb-norm": "u-norm"}
    fake.record([EVENT | {"sandbox_id": "sb-vip"},
                 EVENT | {"sandbox_id": "sb-norm"}])

    for key in ("user_type", "-user_type"):
        response = test_client.get("/api/sandboxes", params={"sort": key})
        assert response.status_code == 200
        assert response.json()["sort"] == key


def test_list_sandboxes_invalid_user_type_rejected(client):
    test_client, _ = client

    assert test_client.get(
        "/api/sandboxes", params={"user_type": "premium"}
    ).status_code == 422


def test_list_sandbox_times(client):
    """One row per sandbox; a never-accessed sandbox reports its creation
    time as the latest request time."""
    test_client, fake = client
    fake.user_ids = {"sb-a": "u-1"}
    fake.record([
        EVENT | {"sandbox_id": "sb-a"},
        {**EVENT, "sandbox_id": "sb-b", "request_time": "2026-08-21T09:24:12.252+08:00"},
    ])
    # Discovered in the cluster but never accessed: no request_time, so
    # the row falls back to the creation timestamp.
    fake.upsert_discovered_sandboxes([{
        "name": "sb-c",
        "created_at": datetime(2026, 8, 19, tzinfo=timezone.utc),
        "user_id": "u-2",
    }])

    response = test_client.get("/api/sandboxes/times")

    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 3
    by_sandbox = {item["sandbox_id"]: item for item in data["items"]}
    # Newest first; the never-accessed sandbox falls back to created_at.
    assert [item["sandbox_id"] for item in data["items"]] == ["sb-b", "sb-a", "sb-c"]
    assert by_sandbox["sb-a"]["user_id"] == "u-1"
    assert by_sandbox["sb-a"]["request_time"] == "2026-08-20T09:24:12+08:00"
    assert by_sandbox["sb-c"]["user_id"] == "u-2"
    assert by_sandbox["sb-c"]["request_time"] == by_sandbox["sb-c"]["created_at"]
    assert by_sandbox["sb-c"]["created_at"] == "2026-08-19T00:00:00Z"


def test_list_sandbox_times_includes_deleted_and_paginates(client):
    """Deleted sandboxes stay in the listing (audit history), and
    limit/offset paginate it."""
    test_client, fake = client
    fake.record([
        {**EVENT, "sandbox_id": f"sb-{index:02d}",
         "request_time": f"2026-08-2{index}T09:24:12.252+08:00"}
        for index in range(3)
    ])
    fake.sync_deleted_flags(["sb-00"])  # sb-01 and sb-02 are removed

    response = test_client.get("/api/sandboxes/times", params={"limit": 1})

    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 3
    assert [item["sandbox_id"] for item in data["items"]] == ["sb-02"]

    response = test_client.get(
        "/api/sandboxes/times", params={"limit": 2, "offset": 1}
    )
    assert [item["sandbox_id"] for item in response.json()["items"]] == ["sb-01", "sb-00"]


def test_list_sandbox_times_excludes_whitelisted_users(monkeypatch, client):
    """Whitelisted users' sandboxes stay out of /api/sandboxes/times;
    sandboxes without a user id are still listed."""
    monkeypatch.setattr(main, "WHITELIST_USERS", ["u-1"])
    test_client, fake = client
    fake.user_ids = {"sb-a": "u-1", "sb-b": "u-2"}
    fake.record([
        EVENT | {"sandbox_id": "sb-a"},
        {**EVENT, "sandbox_id": "sb-b", "request_time": "2026-08-21T09:24:12.252+08:00"},
        {**EVENT, "sandbox_id": "sb-c"},  # no user id - stays listed
    ])

    response = test_client.get("/api/sandboxes/times")

    assert response.status_code == 200
    data = response.json()
    # sb-a (whitelisted user) is gone; sb-b and the bare sb-c remain.
    assert data["total"] == 2
    assert {item["sandbox_id"] for item in data["items"]} == {"sb-b", "sb-c"}


# ---------------------------------------------------------------------------
# Host-sandbox query (GET /api/host-sandboxes)
# ---------------------------------------------------------------------------

def test_list_host_sandboxes(client):
    """One row per live sandbox on the host, least-recently-active first."""
    test_client, fake = client
    now = datetime.now(timezone.utc).replace(microsecond=0)
    _seed(fake, "sb-recent", "10.0.0.1", user_id="u-1",
          request_time=now - timedelta(days=1))
    _seed(fake, "sb-idle", "10.0.0.1", user_id="u-2",
          request_time=now - timedelta(days=5))
    # On another host - excluded.
    _seed(fake, "sb-other", "10.0.0.2", user_id="u-3",
          request_time=now - timedelta(days=1))

    response = test_client.get("/api/host-sandboxes", params={"node_ip": "10.0.0.1"})

    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 2
    # Least-recently-active first: sb-idle (5 days) before sb-recent (1 day).
    assert [item["sandbox_id"] for item in data["items"]] == ["sb-idle", "sb-recent"]
    by_sb = {item["sandbox_id"]: item for item in data["items"]}
    assert by_sb["sb-recent"]["user_id"] == "u-1"
    # FastAPI encodes UTC datetimes with a trailing Z.
    assert by_sb["sb-recent"]["request_time"] == (
        now - timedelta(days=1)
    ).isoformat().replace("+00:00", "Z")


def test_list_host_sandboxes_stale_days(client):
    """stale_days keeps only sandboxes idle for more than N days; a
    never-accessed sandbox is stale since its creation time."""
    test_client, fake = client
    now = datetime.now(timezone.utc).replace(microsecond=0)
    _seed(fake, "sb-recent", "10.0.0.1", user_id="u-1",
          request_time=now - timedelta(days=1))
    _seed(fake, "sb-stale", "10.0.0.1", user_id="u-2",
          request_time=now - timedelta(days=10))
    # Never accessed but created long ago - stale since creation.
    _seed(fake, "sb-old-fresh", "10.0.0.1", user_id="u-3",
          created_at=now - timedelta(days=20))

    response = test_client.get(
        "/api/host-sandboxes", params={"node_ip": "10.0.0.1", "stale_days": 7}
    )

    assert response.status_code == 200
    data = response.json()
    sbs = {item["sandbox_id"] for item in data["items"]}
    assert sbs == {"sb-stale", "sb-old-fresh"}
    unaccessed = next(
        item for item in data["items"] if item["sandbox_id"] == "sb-old-fresh"
    )
    # request_time is null for never-accessed; created_at carries the time.
    assert unaccessed["request_time"] is None
    assert unaccessed["created_at"] == (
        now - timedelta(days=20)
    ).isoformat().replace("+00:00", "Z")


def test_list_host_sandboxes_excludes_deleted(client):
    """Deleted sandboxes on the host are hidden - only live ones sit on a host."""
    test_client, fake = client
    now = datetime.now(timezone.utc).replace(microsecond=0)
    _seed(fake, "sb-live", "10.0.0.1", user_id="u-1",
          request_time=now - timedelta(days=1))
    _seed(fake, "sb-gone", "10.0.0.1", user_id="u-2",
          request_time=now - timedelta(days=10))
    fake.sync_deleted_flags(["sb-live"])  # sb-gone removed from the cluster

    response = test_client.get("/api/host-sandboxes", params={"node_ip": "10.0.0.1"})

    assert response.status_code == 200
    sbs = {item["sandbox_id"] for item in response.json()["items"]}
    assert sbs == {"sb-live"}


def test_list_host_sandboxes_strips_port(client):
    """An Alertmanager-style instance label (IP:port) is accepted; the
    :port is stripped before matching node_ip."""
    test_client, fake = client
    _seed(fake, "sb-a", "10.0.0.1", user_id="u-1",
          request_time=datetime.now(timezone.utc).replace(microsecond=0))

    response = test_client.get(
        "/api/host-sandboxes", params={"node_ip": "10.0.0.1:9100"}
    )

    assert response.status_code == 200
    assert response.json()["total"] == 1


def test_list_host_sandboxes_bearer_auth(monkeypatch, client):
    """/api/host-sandboxes accepts a session cookie or a Bearer password."""
    monkeypatch.setattr(main, "UI_PASSWORD", "secret")
    test_client, fake = client
    _seed(fake, "sb-a", "10.0.0.1", user_id="u-1",
          request_time=datetime.now(timezone.utc).replace(microsecond=0))

    # No credentials -> 401.
    assert test_client.get(
        "/api/host-sandboxes", params={"node_ip": "10.0.0.1"}
    ).status_code == 401

    # Bearer password -> 200.
    response = test_client.get(
        "/api/host-sandboxes",
        params={"node_ip": "10.0.0.1"},
        headers={"Authorization": "Bearer secret"},
    )
    assert response.status_code == 200
    assert response.json()["total"] == 1


def test_list_host_sandboxes_query_failure_returns_502(client):
    test_client, fake = client
    fake.fail = True

    assert (
        test_client.get("/api/host-sandboxes", params={"node_ip": "10.0.0.1"}).status_code
        == 502
    )


def test_list_requests_filter_by_user(client):
    """user_id on /api/requests returns every request of the user's sandboxes."""
    test_client, fake = client
    fake.user_ids = {"sb-a": "u-1", "sb-b": "u-1"}
    fake.record([EVENT | {"sandbox_id": "sb-a"},
                 EVENT | {"sandbox_id": "sb-b"},
                 EVENT | {"sandbox_id": "sb-c"}])

    response = test_client.get("/api/requests", params={"user_id": "u-1"})

    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 2
    assert {item["sandbox_id"] for item in data["items"]} == {"sb-a", "sb-b"}
    assert all(item["user_id"] == "u-1" for item in data["items"])

    # Sandbox filter still works and carries the user_id.
    response = test_client.get("/api/requests", params={"sandbox_id": "sb-c"})
    assert response.json()["total"] == 1
    assert response.json()["items"][0]["user_id"] is None


def test_list_sandboxes_rejects_invalid_time_range(client):
    test_client, _ = client

    response = test_client.get(
        "/api/sandboxes", params={"time_from": "not-a-timestamp"}
    )

    assert response.status_code == 422


def test_list_requests_with_filter(client):
    test_client, fake = client
    fake.record([EVENT, {**EVENT, "sandbox_id": "other"}])

    response = test_client.get("/api/requests", params={"sandbox_id": "test-sandbox"})

    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 1
    assert data["items"][0]["sandbox_id"] == "test-sandbox"


def test_list_requests_pagination(client):
    test_client, fake = client
    fake.record([{**EVENT, "sandbox_id": f"sandbox-{i}"} for i in range(5)])

    response = test_client.get("/api/requests", params={"limit": 2, "offset": 3})

    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 5
    assert len(data["items"]) == 2


def test_list_requests_rejects_invalid_pagination(client):
    test_client, _ = client

    response = test_client.get("/api/requests", params={"limit": 0})

    assert response.status_code == 422


def test_list_query_failure_returns_502(client):
    test_client, fake = client
    fake.fail = True

    assert test_client.get("/api/sandboxes").status_code == 502
    assert test_client.get("/api/requests").status_code == 502


def test_normalize_parses_rfc3339_zulu():
    event = _normalize({**EVENT, "request_time": "2026-08-20T01:24:12.252Z"})

    assert event["request_time"].utcoffset().total_seconds() == 0


def test_normalize_assumes_utc_for_naive_timestamp():
    event = _normalize({**EVENT, "request_time": "2026-08-20T01:24:12"})

    assert event["request_time"].utcoffset().total_seconds() == 0


def test_normalize_truncates_to_seconds():
    event = _normalize({**EVENT, "request_time": "2026-08-20T09:24:12.252953+08:00"})

    assert event["request_time"].isoformat() == "2026-08-20T09:24:12+08:00"


def test_summary_shows_user_current_sandbox(client):
    """The summary row pairs each user with their current (live) sandbox."""
    test_client, fake = client
    # User u-1's current sandbox; a second lean event keeps it live.
    fake.user_ids = {"sb-a": "u-1"}
    fake.record([EVENT | {"sandbox_id": "sb-a"}])

    response = test_client.get("/api/sandboxes")

    assert response.status_code == 200
    (row,) = response.json()["items"]
    assert row["uid"] == "u-1"
    assert row["user_id"] == "u-1"
    assert row["sandbox_id"] == "sb-a"
    assert row["sandbox_count"] == 1


def test_summary_unaccessed_falls_back_to_deleted_request_time(client):
    """A user whose current sandbox was never accessed reports the latest
    request of their deleted sandboxes as the group's request_time."""
    test_client, fake = client
    fake.user_ids = {"sb-old": "u-1", "sb-new": "u-1"}
    # The user's previous sandbox was accessed, then removed by the sync.
    fake.record([
        {**EVENT, "sandbox_id": "sb-old", "request_time": "2026-08-18T09:24:12.252+08:00"},
        {**EVENT, "sandbox_id": "sb-old", "request_time": "2026-08-19T09:24:12.252+08:00"},
    ])
    fake.sync_deleted_flags([])  # sb-old is gone from the cluster
    # The current sandbox exists but has no access records yet.
    fake.upsert_discovered_sandboxes([{
        "name": "sb-new",
        "created_at": datetime(2026, 8, 20, tzinfo=timezone.utc),
        "user_id": "u-1",
    }])

    response = test_client.get("/api/sandboxes")

    assert response.status_code == 200
    (row,) = response.json()["items"]
    assert row["uid"] == "u-1"
    assert row["sandbox_id"] == "sb-new"
    assert row["accessed"] is False  # the current sandbox stays 未访问
    # Falls back to the deleted sandbox's latest request, not its first.
    assert row["request_time"] == "2026-08-19T09:24:12+08:00"
    # Only the (unaccessed) current sandbox counts towards the sum.
    assert row["request_count"] == 0


def test_summary_no_fallback_when_current_sandbox_accessed(client):
    """An accessed current sandbox keeps its own request time even when the
    user's deleted sandbox was requested more recently."""
    test_client, fake = client
    fake.user_ids = {"sb-old": "u-1", "sb-new": "u-1"}
    fake.record([
        # Deleted sandbox requested AFTER the current one - still ignored.
        {**EVENT, "sandbox_id": "sb-old", "request_time": "2026-08-21T09:24:12.252+08:00"},
    ])
    fake.sync_deleted_flags(["sb-new"])
    fake.record([{**EVENT, "sandbox_id": "sb-new"}])

    response = test_client.get("/api/sandboxes")

    assert response.status_code == 200
    (row,) = response.json()["items"]
    assert row["accessed"] is True
    assert row["request_time"] == "2026-08-20T09:24:12+08:00"


def test_summary_time_filter_matches_fallback_request_time(client):
    """time_from/time_to bind the effective request time, so a group whose
    current sandbox is unaccessed is found via its deleted history."""
    test_client, fake = client
    fake.user_ids = {"sb-old": "u-1", "sb-new": "u-1"}
    fake.record([
        {**EVENT, "sandbox_id": "sb-old", "request_time": "2026-08-19T09:24:12.252+08:00"},
    ])
    fake.sync_deleted_flags([])
    fake.upsert_discovered_sandboxes([{
        "name": "sb-new",
        "created_at": datetime(2026, 8, 20, tzinfo=timezone.utc),
        "user_id": "u-1",
    }])

    # The deleted sandbox's request (Aug 19) is inside the window.
    response = test_client.get(
        "/api/sandboxes",
        params={"time_from": "2026-08-19T00:00:00Z", "time_to": "2026-08-19T23:59:59Z"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 1
    assert data["items"][0]["request_time"] == "2026-08-19T09:24:12+08:00"

    # Outside the window the group falls out (NULL comparisons are not TRUE).
    response = test_client.get(
        "/api/sandboxes", params={"time_from": "2026-08-20T00:00:00Z"}
    )
    assert response.status_code == 200
    assert response.json()["total"] == 0


def test_user_details_include_deleted_history(client):
    """/api/requests?user_id= covers removed sandboxes too, flagged."""
    test_client, fake = client
    fake.user_ids = {"sb-old": "u-1", "sb-new": "u-1"}
    fake.record([EVENT | {"sandbox_id": "sb-old"}])
    fake.deleted_ids.add("sb-old")  # the sync removed the old sandbox
    fake.record([EVENT | {"sandbox_id": "sb-new"}])

    response = test_client.get("/api/requests", params={"user_id": "u-1"})

    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 2
    by_sandbox = {item["sandbox_id"]: item for item in data["items"]}
    assert by_sandbox["sb-old"]["sandbox_deleted"] is True
    assert by_sandbox["sb-new"]["sandbox_deleted"] is False
    assert all(item["user_id"] == "u-1" for item in data["items"])


class FakeK8sClient:
    def __init__(self, names, created_at=None, pod_nodes=None):
        self.names = names
        self.created_at = created_at
        # sandbox_id -> node IP; defaults to none (no pods listed).
        self.pod_nodes = pod_nodes or {}
        self.calls = 0

    def list_batch_sandboxes(self, namespace):
        self.calls += 1
        return [{"name": name, "created_at": self.created_at} for name in self.names]

    def list_sandbox_pod_nodes(self, namespace):
        self.calls += 1
        return dict(self.pod_nodes)


def test_sync_deleted_marks_missing_sandboxes(monkeypatch, client):
    """Sandbox ids absent from the k8s resource names are marked deleted."""
    monkeypatch.setattr(main, "K8S_NAMESPACE", "opensandbox")
    test_client, fake = client
    fake.record([EVENT, {**EVENT, "sandbox_id": "other"}])
    fake_k8s = FakeK8sClient(["test-sandbox"])
    monkeypatch.setattr(main.k8s, "K8sClient", lambda _: fake_k8s)
    main.app.state.k8s_client = fake_k8s
    try:
        response = test_client.post("/api/sync-deleted")
    finally:
        main.app.state.k8s_client = None

    assert response.status_code == 200
    data = response.json()
    assert data["namespace"] == "opensandbox"
    assert data["live"] == 1
    assert data["deleted"] == 1
    assert data["restored"] == 0
    assert fake.deleted_ids == {"other"}

    # Deleted sandboxes no longer appear in the summary listing (已删除
    # rows are hidden); their audit history stays on the details page.
    listing = test_client.get("/api/sandboxes")
    assert listing.status_code == 200
    assert listing.json()["total"] == 1
    assert [i["uid"] for i in listing.json()["items"]] == ["test-sandbox"]


def test_sync_deleted_restores_reappeared_sandbox(monkeypatch, client):
    """A sandbox id that reappears in the cluster is un-deleted."""
    monkeypatch.setattr(main, "K8S_NAMESPACE", "opensandbox")
    test_client, fake = client
    fake.record([EVENT, {**EVENT, "sandbox_id": "other"}])
    fake_k8s = FakeK8sClient([])
    monkeypatch.setattr(main.k8s, "K8sClient", lambda _: fake_k8s)
    main.app.state.k8s_client = fake_k8s
    try:
        assert test_client.post("/api/sync-deleted").json()["deleted"] == 2

        fake_k8s.names = ["test-sandbox", "other"]
        response = test_client.post("/api/sync-deleted")
    finally:
        main.app.state.k8s_client = None

    assert response.status_code == 200
    assert response.json()["restored"] == 2
    assert fake.deleted_ids == set()
    assert test_client.get("/api/sandboxes").json()["total"] == 2


def test_sync_deleted_requires_namespace(monkeypatch, client):
    """Without AUDIT_K8S_NAMESPACE the sync endpoint rejects with 400."""
    monkeypatch.setattr(main, "K8S_NAMESPACE", "")
    test_client, _ = client

    assert test_client.post("/api/sync-deleted").status_code == 400


def test_sync_deleted_k8s_failure_returns_502(monkeypatch, client):
    monkeypatch.setattr(main, "K8S_NAMESPACE", "opensandbox")
    test_client, _ = client

    class BrokenK8sClient:
        def list_batch_sandboxes(self, namespace):
            raise main.k8s.K8sError("api down")

    monkeypatch.setattr(main.k8s, "K8sClient", lambda _: BrokenK8sClient())
    main.app.state.k8s_client = None
    response = test_client.post("/api/sync-deleted")

    assert response.status_code == 502


def test_sync_deleted_requires_auth(monkeypatch, client):
    monkeypatch.setattr(main, "K8S_NAMESPACE", "opensandbox")
    monkeypatch.setattr(main, "UI_PASSWORD", "secret")
    test_client, _ = client

    assert test_client.post("/api/sync-deleted").status_code == 401


def test_sync_discovers_unaccessed_sandboxes(monkeypatch, client):
    """Cluster sandbox ids missing from the database are inserted as unaccessed rows."""
    monkeypatch.setattr(main, "K8S_NAMESPACE", "opensandbox")
    test_client, fake = client
    fake.record([EVENT])
    created = datetime(2026, 8, 30, 4, 5, 6, tzinfo=timezone.utc)
    fake_k8s = FakeK8sClient(["test-sandbox", "fresh"], created_at=created)
    monkeypatch.setattr(main.k8s, "K8sClient", lambda _: fake_k8s)
    main.app.state.k8s_client = fake_k8s
    try:
        response = test_client.post("/api/sync-deleted")
    finally:
        main.app.state.k8s_client = None

    assert response.status_code == 200
    data = response.json()
    assert data["discovered"] == 1
    # "test-sandbox" already had a row without created_at -> backfilled.
    assert data["backfilled"] == 1
    assert data["deleted"] == 0

    # The discovered sandbox shows up in the summary API as never accessed,
    # carrying the BatchSandbox creationTimestamp.
    listing = test_client.get("/api/sandboxes")
    assert listing.status_code == 200
    items = {item["uid"]: item for item in listing.json()["items"]}
    assert set(items) == {"test-sandbox", "fresh"}
    assert items["fresh"]["accessed"] is False
    assert items["fresh"]["request_count"] == 0
    assert items["fresh"]["request_time"] is None
    assert items["fresh"]["created_at"] == "2026-08-30T04:05:06Z"
    assert items["test-sandbox"]["accessed"] is True
    # Backfilled from the sync (discovery happened mid-test).
    assert items["test-sandbox"]["created_at"] == "2026-08-30T04:05:06Z"

    # A second sync discovers nothing new.
    main.app.state.k8s_client = fake_k8s
    try:
        assert test_client.post("/api/sync-deleted").json()["discovered"] == 0
    finally:
        main.app.state.k8s_client = None


def test_sync_backfills_creation_timestamp(monkeypatch, client):
    """Existing rows missing created_at get it backfilled from the resource."""
    monkeypatch.setattr(main, "K8S_NAMESPACE", "opensandbox")
    test_client, fake = client
    # The sandbox was accessed before the first sync ran, so its row
    # exists but has no creation timestamp.
    fake.record([EVENT])
    created = datetime(2026, 8, 19, 8, 30, 0, tzinfo=timezone.utc)
    fake_k8s = FakeK8sClient(["test-sandbox"], created_at=created)
    monkeypatch.setattr(main.k8s, "K8sClient", lambda _: fake_k8s)
    main.app.state.k8s_client = fake_k8s
    try:
        response = test_client.post("/api/sync-deleted")
    finally:
        main.app.state.k8s_client = None

    assert response.status_code == 200
    data = response.json()
    assert data["discovered"] == 0
    assert data["backfilled"] == 1

    items = {
        item["uid"]: item
        for item in test_client.get("/api/sandboxes").json()["items"]
    }
    assert items["test-sandbox"]["created_at"] == "2026-08-19T08:30:00Z"
    assert items["test-sandbox"]["accessed"] is True

    # Re-syncing with the same timestamp backfills nothing more.
    main.app.state.k8s_client = fake_k8s
    try:
        assert test_client.post("/api/sync-deleted").json()["backfilled"] == 0
    finally:
        main.app.state.k8s_client = None


def test_sync_updates_node_ips(monkeypatch, client):
    """The sync refreshes node_ip from the sandbox pods' host IPs."""
    monkeypatch.setattr(main, "K8S_NAMESPACE", "opensandbox")
    test_client, fake = client
    fake.record([EVENT, {**EVENT, "sandbox_id": "other"}])
    fake_k8s = FakeK8sClient(
        ["test-sandbox", "other"],
        pod_nodes={"test-sandbox": "10.0.0.1", "other": "10.0.0.2"},
    )
    monkeypatch.setattr(main.k8s, "K8sClient", lambda _: fake_k8s)
    main.app.state.k8s_client = fake_k8s
    try:
        response = test_client.post("/api/sync-deleted")
    finally:
        main.app.state.k8s_client = None

    assert response.status_code == 200
    data = response.json()
    assert data["node_updated"] == 2

    # The summary groups don't carry node_ip (a user may span nodes), but
    # searching by node IP finds the group whose member sits on that node.
    listing = test_client.get("/api/sandboxes", params={"search": "10.0.0.1"})
    assert listing.status_code == 200
    assert listing.json()["total"] == 1
    assert listing.json()["items"][0]["uid"] == "test-sandbox"

    # A rescheduled pod (new host IP) overwrites the old value; unchanged
    # rows are not counted again.
    fake_k8s.pod_nodes = {"test-sandbox": "10.0.0.9", "other": "10.0.0.2"}
    main.app.state.k8s_client = fake_k8s
    try:
        response = test_client.post("/api/sync-deleted")
    finally:
        main.app.state.k8s_client = None
    assert response.json()["node_updated"] == 1
    listing = test_client.get("/api/sandboxes", params={"search": "10.0.0.9"})
    assert listing.json()["total"] == 1
    assert listing.json()["items"][0]["uid"] == "test-sandbox"


def test_search_by_ip_finds_unaccessed_sandboxes(monkeypatch, client):
    """IP search also matches discovered-but-never-accessed rows."""
    monkeypatch.setattr(main, "K8S_NAMESPACE", "opensandbox")
    test_client, fake = client
    fake.upsert_discovered_sandboxes([{"name": "fresh", "created_at": None}])
    fake.update_node_ips({"fresh": "10.0.0.5"})

    listing = test_client.get("/api/sandboxes", params={"search": "10.0.0.5"})

    assert listing.status_code == 200
    assert listing.json()["total"] == 1
    assert listing.json()["items"][0]["uid"] == "fresh"


def test_discovered_sandbox_becomes_accessed_on_first_event(monkeypatch, client):
    """The first audit event for a discovered sandbox flips it to accessed."""
    monkeypatch.setattr(main, "K8S_NAMESPACE", "opensandbox")
    test_client, fake = client
    fake.upsert_discovered_sandboxes([{"name": "fresh", "created_at": None}])

    items = {
        item["uid"]: item
        for item in test_client.get("/api/sandboxes").json()["items"]
    }
    assert items["fresh"]["accessed"] is False

    test_client.post("/events", json={**EVENT, "sandbox_id": "fresh"})

    items = {
        item["uid"]: item
        for item in test_client.get("/api/sandboxes").json()["items"]
    }
    assert items["fresh"]["accessed"] is True


# ---------------------------------------------------------------------------
# Alertmanager webhook (POST /alerts) and alerts query (GET /api/alerts)
# ---------------------------------------------------------------------------

def test_record_alertmanager_alerts(client):
    """A notification's alerts are appended as delivered, normalized."""
    test_client, fake = client

    response = test_client.post("/alerts", json=ALERTMANAGER_PAYLOAD)

    assert response.status_code == 200
    assert response.json() == {"accepted": 2}
    assert len(fake.alerts) == 2
    first = fake.alerts[0]
    assert first["fingerprint"] == "abc123"
    assert first["status"] == "firing"
    assert first["receiver"] == "audit-webhook"
    assert first["group_key"] == '{}:{"alertname":"HighMemory"}'
    assert first["labels"]["alertname"] == "HighMemory"
    assert first["annotations"]["summary"] == "内存使用过高"
    assert first["generator_url"] == "http://prometheus:9090/graph"
    # Nanosecond precision is truncated to whole seconds.
    assert first["starts_at"].isoformat() == "2026-09-24T08:00:00+00:00"
    # Alertmanager's zero endsAt ("still firing") becomes NULL.
    assert first["ends_at"] is None
    second = fake.alerts[1]
    assert second["status"] == "resolved"
    assert second["ends_at"].isoformat() == "2026-09-24T09:00:00+00:00"


def test_record_alerts_empty_notification(client):
    """A notification without alerts is accepted but stores nothing."""
    test_client, fake = client

    assert test_client.post("/alerts", json={"version": "4", "alerts": []}).json() == {
        "accepted": 0
    }
    # A body without an alerts key defaults to an empty list.
    assert test_client.post("/alerts", json={"version": "4"}).json() == {"accepted": 0}
    assert fake.alerts == []


def test_record_alerts_invalid_payload(client):
    test_client, fake = client

    response = test_client.post(
        "/alerts", json={"alerts": [{"labels": "not-a-dict"}]}
    )

    assert response.status_code == 422
    assert fake.alerts == []


def test_alerts_truncated_notification_logs_warning(client, caplog):
    """truncatedAlerts > 0 warns - some alerts never arrived."""
    test_client, _ = client

    with caplog.at_level("WARNING", logger="audit-webhook"):
        test_client.post(
            "/alerts", json={**ALERTMANAGER_PAYLOAD, "truncatedAlerts": 3}
        )

    assert "truncated 3 alerts" in caplog.text


def test_alerts_store_failure_returns_502(client):
    test_client, fake = client
    fake.fail = True

    response = test_client.post("/alerts", json=ALERTMANAGER_PAYLOAD)

    assert response.status_code == 502


def test_alerts_ingestion_open_without_token(client):
    """With [alerts] auth_token unset (the fixture default), POST /alerts
    takes no credentials - the same as event ingestion."""
    test_client, _ = client

    assert test_client.post("/alerts", json=ALERTMANAGER_PAYLOAD).status_code == 200


def test_alerts_ingestion_bearer_token(monkeypatch, client):
    """With [alerts] auth_token set, POST /alerts requires it as a
    Bearer token; missing or wrong tokens are rejected."""
    monkeypatch.setattr(main, "ALERT_AUTH_TOKEN", "tok-1")
    test_client, fake = client

    # No header -> 401, nothing stored.
    response = test_client.post("/alerts", json=ALERTMANAGER_PAYLOAD)
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"
    assert fake.alerts == []

    # Wrong token -> 401.
    response = test_client.post(
        "/alerts",
        json=ALERTMANAGER_PAYLOAD,
        headers={"Authorization": "Bearer wrong"},
    )
    assert response.status_code == 401
    assert fake.alerts == []

    # Correct token -> recorded.
    response = test_client.post(
        "/alerts",
        json=ALERTMANAGER_PAYLOAD,
        headers={"Authorization": "Bearer tok-1"},
    )
    assert response.status_code == 200
    assert response.json() == {"accepted": 2}
    assert len(fake.alerts) == 2


def test_alerts_ingestion_ignores_ui_password(monkeypatch, client):
    """The UI password never applies to alert ingestion - a UI login is a
    human credential, the alert token is the machine credential."""
    monkeypatch.setattr(main, "UI_PASSWORD", "secret")
    test_client, _ = client

    response = test_client.post("/alerts", json=ALERTMANAGER_PAYLOAD)

    assert response.status_code == 200


def test_bearer_credentials_are_not_interchangeable(monkeypatch, client):
    """The two bearer credentials only work on their own surface: the
    alert token does not unlock query APIs, the UI password does not
    deliver alerts."""
    monkeypatch.setattr(main, "UI_PASSWORD", "ui-secret")
    monkeypatch.setattr(main, "ALERT_AUTH_TOKEN", "alert-secret")
    test_client, _ = client

    # Alert token on a query API -> 401.
    assert (
        test_client.get(
            "/api/sandboxes/times",
            headers={"Authorization": "Bearer alert-secret"},
        ).status_code
        == 401
    )
    # UI password as the alert token -> 401.
    assert (
        test_client.post(
            "/alerts",
            json=ALERTMANAGER_PAYLOAD,
            headers={"Authorization": "Bearer ui-secret"},
        ).status_code
        == 401
    )
    # Each credential works on its own surface.
    assert (
        test_client.post(
            "/alerts",
            json=ALERTMANAGER_PAYLOAD,
            headers={"Authorization": "Bearer alert-secret"},
        ).status_code
        == 200
    )
    assert (
        test_client.get(
            "/api/sandboxes/times",
            headers={"Authorization": "Bearer ui-secret"},
        ).status_code
        == 200
    )


def test_list_alerts(client):
    test_client, _ = client
    assert test_client.post("/alerts", json=ALERTMANAGER_PAYLOAD).status_code == 200

    response = test_client.get("/api/alerts")

    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 2
    # Newest delivery first (id DESC): the second alert of the batch.
    assert data["items"][0]["fingerprint"] == "def456"
    assert data["items"][0]["status"] == "resolved"
    assert data["items"][0]["labels"] == {"alertname": "HighCPU", "instance": "pod-2"}
    assert data["items"][0]["starts_at"] == "2026-09-23T08:00:00Z"

    # status filter
    data = test_client.get("/api/alerts", params={"status": "firing"}).json()
    assert data["total"] == 1
    assert data["items"][0]["fingerprint"] == "abc123"

    # search hits labels (alertname, case-insensitive) and annotations
    assert (
        test_client.get("/api/alerts", params={"search": "highcpu"}).json()["total"]
        == 1
    )
    assert (
        test_client.get("/api/alerts", params={"search": "POD-2"}).json()["total"]
        == 1
    )
    assert (
        test_client.get("/api/alerts", params={"search": "内存"}).json()["total"] == 1
    )
    # ...and fingerprints / receivers
    assert (
        test_client.get("/api/alerts", params={"search": "abc123"}).json()["total"]
        == 1
    )
    assert (
        test_client.get(
            "/api/alerts", params={"search": "audit-webhook"}
        ).json()["total"]
        == 2
    )
    # No hit
    assert test_client.get("/api/alerts", params={"search": "nope"}).json()["total"] == 0

    # pagination
    data = test_client.get("/api/alerts", params={"limit": 1, "offset": 1}).json()
    assert data["total"] == 2
    assert [item["fingerprint"] for item in data["items"]] == ["abc123"]


def test_list_alerts_invalid_params(client):
    test_client, _ = client

    # status must be firing/resolved, limit must be >= 1.
    assert test_client.get("/api/alerts", params={"status": "silenced"}).status_code == 422
    assert test_client.get("/api/alerts", params={"limit": 0}).status_code == 422


def test_list_alerts_requires_auth(monkeypatch, client):
    """GET /api/alerts follows the other query APIs: session required when
    server.ui_password is set."""
    monkeypatch.setattr(main, "UI_PASSWORD", "secret")
    test_client, _ = client

    assert test_client.get("/api/alerts").status_code == 401


def test_normalize_alert_zero_ends_at_is_none():
    row = _normalize_alert(
        {
            "fingerprint": "f",
            "status": "firing",
            "starts_at": "2026-09-24T08:00:00.999Z",
            "ends_at": "0001-01-01T00:00:00Z",
        }
    )

    assert row["ends_at"] is None
    assert row["starts_at"].isoformat() == "2026-09-24T08:00:00+00:00"


def test_normalize_alert_naive_timestamp_assumed_utc():
    row = _normalize_alert({"starts_at": "2026-09-24T08:00:00"})

    assert row["starts_at"].utcoffset().total_seconds() == 0


def test_normalize_alert_defaults():
    """Missing optional fields degrade to sane defaults, not errors."""
    row = _normalize_alert({})

    assert row["fingerprint"] == ""
    assert row["status"] == "firing"
    assert row["labels"] == {}
    assert row["annotations"] == {}
    assert row["starts_at"] is None
    assert row["ends_at"] is None


# ---------------------------------------------------------------------------
# Memory-alert stale-user lookup (firing host memory alerts -> users on
# the host not accessed for > [alerts] stale_days days, VIP excluded)
# ---------------------------------------------------------------------------

def _memory_alert_payload(
    instance="10.0.0.1:9100", status="firing", alertname="HighMemory", fingerprint="mem-1"
):
    """A one-alert Alertmanager notification carrying a host memory alert
    (``instance`` is the node_exporter-style ``IP:port`` host label)."""
    labels = {"alertname": alertname, "severity": "warning"}
    if instance is not None:
        labels["instance"] = instance
    return {
        "version": "4",
        "receiver": "audit-webhook",
        "status": status,
        "alerts": [
            {
                "status": status,
                "labels": labels,
                "annotations": {"summary": "内存使用过高"},
                "startsAt": "2026-09-24T08:00:00Z",
                "endsAt": (
                    "0001-01-01T00:00:00Z"
                    if status == "firing"
                    else "2026-09-25T08:00:00Z"
                ),
                "fingerprint": fingerprint,
            }
        ],
    }


def _seed(fake, sandbox_id, node_ip, user_id=None, request_time=None, created_at=None):
    """Put a summary row into the fake store: ``request_time`` records an
    access, else the sandbox is only discovered (``created_at`` set,
    never accessed)."""
    if user_id is not None:
        fake.user_ids[sandbox_id] = user_id
    fake.node_ips[sandbox_id] = node_ip
    if request_time is not None:
        fake.record([{**EVENT, "sandbox_id": sandbox_id, "request_time": request_time}])
    else:
        fake.upsert_discovered_sandboxes(
            [{"name": sandbox_id, "created_at": created_at, "user_id": user_id}]
        )


def test_memory_alert_lists_stale_users(monkeypatch, client, caplog):
    """A firing alert whose alertname is configured queries the users on
    its host (instance label, port stripped): the stale ones come back in
    the response and the log, the recently active ones do not."""
    monkeypatch.setattr(main, "MEMORY_ALERT_NAMES", ["HighMemory"])
    test_client, fake = client
    now = datetime.now(timezone.utc).replace(microsecond=0)
    stale_since = now - timedelta(days=10)
    _seed(
        fake, "sb-stale", "10.0.0.1",
        user_id="u-stale", request_time=stale_since,
    )
    _seed(
        fake, "sb-recent", "10.0.0.1",
        user_id="u-recent", request_time=now - timedelta(days=1),
    )

    with caplog.at_level("WARNING", logger="audit-webhook"):
        response = test_client.post("/alerts", json=_memory_alert_payload())

    assert response.status_code == 200
    data = response.json()
    assert data["accepted"] == 1
    assert fake.stale_queries == [("10.0.0.1", 7, [])]
    (host_entry,) = data["stale_users"]
    assert host_entry["host"] == "10.0.0.1"
    assert host_entry["alertname"] == "HighMemory"
    (user,) = host_entry["users"]
    assert user["user_id"] == "u-stale"
    assert user["sandbox_id"] == "sb-stale"
    assert user["last_access"] == stale_since.isoformat()
    assert user["days"] == 10
    # The stale user and its host show up in the log.
    assert "u-stale" in caplog.text
    assert "10.0.0.1" in caplog.text


def test_memory_alert_excludes_vip_and_other_hosts(monkeypatch, client):
    """VIP (whitelisted) users stay out of the list, and so do users
    whose sandboxes sit on other nodes."""
    monkeypatch.setattr(main, "WHITELIST_USERS", ["u-vip"])
    monkeypatch.setattr(main, "MEMORY_ALERT_NAMES", ["HighMemory"])
    test_client, fake = client
    now = datetime.now(timezone.utc).replace(microsecond=0)
    _seed(fake, "sb-vip", "10.0.0.1", user_id="u-vip",
          request_time=now - timedelta(days=10))
    _seed(fake, "sb-other", "10.0.0.2", user_id="u-other",
          request_time=now - timedelta(days=10))
    _seed(fake, "sb-stale", "10.0.0.1", user_id="u-stale",
          request_time=now - timedelta(days=10))

    response = test_client.post("/alerts", json=_memory_alert_payload())

    assert response.status_code == 200
    (host_entry,) = response.json()["stale_users"]
    users = {user["user_id"] for user in host_entry["users"]}
    assert users == {"u-stale"}
    # The whitelist reached the store query.
    assert fake.stale_queries == [("10.0.0.1", 7, ["u-vip"])]


def test_memory_alert_unconfigured_alertname_skips_lookup(client):
    """Alerts whose alertname is not in [alerts] memory_alert_names do
    not trigger a lookup; the response keeps its old shape."""
    test_client, fake = client  # MEMORY_ALERT_NAMES = [] from the fixture

    response = test_client.post("/alerts", json=_memory_alert_payload())

    assert response.status_code == 200
    assert response.json() == {"accepted": 1}
    assert fake.stale_queries == []


def test_resolved_memory_alert_skips_lookup(monkeypatch, client):
    """Only firing memory alerts trigger the lookup - a resolved alert
    needs no action."""
    monkeypatch.setattr(main, "MEMORY_ALERT_NAMES", ["HighMemory"])
    test_client, fake = client
    now = datetime.now(timezone.utc).replace(microsecond=0)
    _seed(fake, "sb-stale", "10.0.0.1", user_id="u-stale",
          request_time=now - timedelta(days=10))

    response = test_client.post(
        "/alerts", json=_memory_alert_payload(status="resolved")
    )

    assert response.status_code == 200
    assert response.json() == {"accepted": 1}
    assert fake.stale_queries == []


def test_memory_alert_never_accessed_counts_from_creation(monkeypatch, client):
    """A never-accessed sandbox is stale since its creation: an old one
    is listed (last_access = created_at), a fresh one is not."""
    monkeypatch.setattr(main, "MEMORY_ALERT_NAMES", ["HighMemory"])
    test_client, fake = client
    now = datetime.now(timezone.utc).replace(microsecond=0)
    old_created = now - timedelta(days=10)
    _seed(fake, "sb-old", "10.0.0.1", user_id="u-old", created_at=old_created)
    _seed(fake, "sb-new", "10.0.0.1", user_id="u-new",
          created_at=now - timedelta(days=1))

    response = test_client.post("/alerts", json=_memory_alert_payload())

    assert response.status_code == 200
    (host_entry,) = response.json()["stale_users"]
    (user,) = host_entry["users"]
    assert user["user_id"] == "u-old"
    assert user["last_access"] == old_created.isoformat()


def test_memory_alert_falls_back_to_deleted_history(monkeypatch, client):
    """A never-accessed current sandbox falls back to the user's deleted
    history (summary-page semantics): recent history keeps the user out,
    old history lists them."""
    monkeypatch.setattr(main, "MEMORY_ALERT_NAMES", ["HighMemory"])
    test_client, fake = client
    now = datetime.now(timezone.utc).replace(microsecond=0)
    # u-1's current sandbox was never accessed; their removed sandbox was
    # last requested 3 days ago -> still active, not stale.
    _seed(fake, "sb-cur-1", "10.0.0.1", user_id="u-1",
          created_at=now - timedelta(days=10))
    _seed(fake, "sb-old-1", "10.0.0.9", user_id="u-1",
          request_time=now - timedelta(days=3))
    fake.sync_deleted_flags(["sb-cur-1"])
    # u-2: same, but the last history request is 10 days old -> stale.
    _seed(fake, "sb-cur-2", "10.0.0.1", user_id="u-2",
          created_at=now - timedelta(days=10))
    _seed(fake, "sb-old-2", "10.0.0.9", user_id="u-2",
          request_time=now - timedelta(days=10))
    fake.sync_deleted_flags(["sb-cur-1", "sb-cur-2"])

    response = test_client.post("/alerts", json=_memory_alert_payload())

    assert response.status_code == 200
    (host_entry,) = response.json()["stale_users"]
    users = {user["user_id"] for user in host_entry["users"]}
    assert users == {"u-2"}


def test_memory_alert_without_instance_label_skipped(monkeypatch, client, caplog):
    """A memory alert without an instance label names no host - it is
    skipped with a warning but still stored."""
    monkeypatch.setattr(main, "MEMORY_ALERT_NAMES", ["HighMemory"])
    test_client, fake = client

    with caplog.at_level("WARNING", logger="audit-webhook"):
        response = test_client.post(
            "/alerts", json=_memory_alert_payload(instance=None)
        )

    assert response.status_code == 200
    assert response.json() == {"accepted": 1}
    assert fake.stale_queries == []
    assert "no instance label" in caplog.text
    assert len(fake.alerts) == 1


def test_memory_alert_lookup_failure_keeps_ingestion(monkeypatch, client, caplog):
    """A failed stale-user lookup is logged but never fails the
    delivery - Alertmanager must not retry and duplicate the alerts."""
    monkeypatch.setattr(main, "MEMORY_ALERT_NAMES", ["HighMemory"])
    test_client, fake = client
    fake.stale_fail = True

    with caplog.at_level("ERROR", logger="audit-webhook"):
        response = test_client.post("/alerts", json=_memory_alert_payload())

    assert response.status_code == 200
    assert response.json() == {"accepted": 1}
    assert len(fake.alerts) == 1
    assert "failed to look up stale users" in caplog.text


def test_memory_alert_dedupes_hosts(monkeypatch, client):
    """Two firing memory alerts naming the same host (with and without a
    port) trigger exactly one lookup."""
    monkeypatch.setattr(main, "MEMORY_ALERT_NAMES", ["HighMemory"])
    test_client, fake = client
    payload = _memory_alert_payload(instance="10.0.0.1:9100", fingerprint="mem-1")
    payload["alerts"].append(
        {
            "status": "firing",
            "labels": {"alertname": "HighMemory", "instance": "10.0.0.1"},
            "annotations": {},
            "startsAt": "2026-09-24T08:00:00Z",
            "endsAt": "0001-01-01T00:00:00Z",
            "fingerprint": "mem-2",
        }
    )

    response = test_client.post("/alerts", json=payload)

    assert response.status_code == 200
    assert response.json()["accepted"] == 2
    assert fake.stale_queries == [("10.0.0.1", 7, [])]


def test_memory_alert_skips_sandboxes_without_user_id(monkeypatch, client):
    """Sandboxes the sync could not resolve a user id for have no user to
    list - they are skipped instead of crashing the lookup."""
    monkeypatch.setattr(main, "MEMORY_ALERT_NAMES", ["HighMemory"])
    test_client, fake = client
    now = datetime.now(timezone.utc).replace(microsecond=0)
    _seed(fake, "sb-bare", "10.0.0.1", request_time=now - timedelta(days=10))

    response = test_client.post("/alerts", json=_memory_alert_payload())

    assert response.status_code == 200
    # No listable user at all -> no stale_users key in the response.
    assert response.json() == {"accepted": 1}
    assert fake.stale_queries == [("10.0.0.1", 7, [])]


# ---------------------------------------------------------------------------
# Auto-stop on memory alerts (firing host memory alerts -> POST the first
# [alerts] stop_limit stale users' user ids to [alerts] stop_url)
# ---------------------------------------------------------------------------

class RecordedStop:
    """Captures the stop-call requests made by main._stop_sandboxes."""

    def __init__(self, statuses=()):
        self.calls = []  # (url, body dict)
        self._statuses = iter(statuses)

    def __call__(self, url, body):
        self.calls.append((url, body))
        status = next(self._statuses, 200)
        if isinstance(status, Exception):
            raise status
        return status


def test_memory_alert_stop_sandboxes_posts_first_users(monkeypatch, client):
    """With [alerts] stop_sandboxes on, a firing memory alert POSTs the
    first stop_limit stale users' user ids (oldest first) to stop_url
    with the configured slug; the response counters report the outcome."""
    monkeypatch.setattr(main, "MEMORY_ALERT_NAMES", ["HighMemory"])
    monkeypatch.setattr(main, "STOP_SANDBOXES", True)
    monkeypatch.setattr(main, "STOP_URL", "http://stop:8000/claw-catalog/stop")
    monkeypatch.setattr(main, "STOP_SLUG", "v20260427")
    monkeypatch.setattr(main, "STOP_LIMIT", 2)
    test_client, fake = client
    now = datetime.now(timezone.utc)
    # Three stale users on the host (sb ids ordered by staleness).
    _seed(fake, "sb-oldest", "10.0.0.1", user_id="u-1",
          request_time=now - timedelta(days=30))
    _seed(fake, "sb-mid", "10.0.0.1", user_id="u-2",
          request_time=now - timedelta(days=20))
    _seed(fake, "sb-late", "10.0.0.1", user_id="u-3",
          request_time=now - timedelta(days=10))
    stop = RecordedStop()
    monkeypatch.setattr(main, "_stop_request", stop)

    response = test_client.post("/alerts", json=_memory_alert_payload())

    assert response.status_code == 200
    # Only the first stop_limit users, most stale first.
    assert stop.calls == [
        (
            "http://stop:8000/claw-catalog/stop",
            {"external_user_id": "u-1", "slug": "v20260427"},
        ),
        (
            "http://stop:8000/claw-catalog/stop",
            {"external_user_id": "u-2", "slug": "v20260427"},
        ),
    ]
    host_entry = response.json()["stale_users"][0]
    assert host_entry["stopped"] == 2
    assert host_entry["failed"] == 0


def test_memory_alert_stop_failure_continues(monkeypatch, client):
    """A failing stop call is logged and counted; the remaining stops
    still run and the ingestion keeps succeeding."""
    monkeypatch.setattr(main, "MEMORY_ALERT_NAMES", ["HighMemory"])
    monkeypatch.setattr(main, "STOP_SANDBOXES", True)
    monkeypatch.setattr(main, "STOP_URL", "http://stop:8000/claw-catalog/stop")
    monkeypatch.setattr(main, "STOP_SLUG", "v20260427")
    monkeypatch.setattr(main, "STOP_LIMIT", 10)
    test_client, fake = client
    now = datetime.now(timezone.utc)
    _seed(fake, "sb-a", "10.0.0.1", user_id="u-1",
          request_time=now - timedelta(days=30))
    _seed(fake, "sb-b", "10.0.0.1", user_id="u-2",
          request_time=now - timedelta(days=20))
    stop = RecordedStop(statuses=[500, 200])
    monkeypatch.setattr(main, "_stop_request", stop)

    response = test_client.post("/alerts", json=_memory_alert_payload())

    assert response.status_code == 200
    assert response.json()["accepted"] == 1
    assert len(stop.calls) == 2
    host_entry = response.json()["stale_users"][0]
    assert host_entry["stopped"] == 1
    assert host_entry["failed"] == 1


def test_memory_alert_stop_disabled_by_default(monkeypatch, client):
    """Without [alerts] stop_sandboxes, no stop request is made."""
    test_client, fake = client
    monkeypatch.setattr(main, "MEMORY_ALERT_NAMES", ["HighMemory"])
    monkeypatch.setattr(main, "STOP_SANDBOXES", False)
    now = datetime.now(timezone.utc)
    _seed(fake, "sb-stale", "10.0.0.1", user_id="u-stale",
          request_time=now - timedelta(days=30))
    stop = RecordedStop()
    monkeypatch.setattr(main, "_stop_request", stop)

    response = test_client.post("/alerts", json=_memory_alert_payload())

    assert response.status_code == 200
    assert stop.calls == []
    host_entry = response.json()["stale_users"][0]
    assert host_entry["stopped"] == 0
    assert host_entry["failed"] == 0


def test_memory_alert_no_stale_users_no_stops(monkeypatch, client):
    """A memory alert whose host has no stale users makes no stop calls."""
    monkeypatch.setattr(main, "MEMORY_ALERT_NAMES", ["HighMemory"])
    monkeypatch.setattr(main, "STOP_SANDBOXES", True)
    test_client, fake = client
    now = datetime.now(timezone.utc)
    _seed(fake, "sb-recent", "10.0.0.1", user_id="u-recent",
          request_time=now - timedelta(days=1))
    stop = RecordedStop()
    monkeypatch.setattr(main, "_stop_request", stop)

    response = test_client.post("/alerts", json=_memory_alert_payload())

    assert response.status_code == 200
    assert stop.calls == []
    # Nothing stale -> no stale_users section at all.
    assert response.json() == {"accepted": 1}


def test_memory_alert_resolved_status_no_stops(monkeypatch, client):
    """A resolved memory alert triggers neither the lookup nor stops."""
    monkeypatch.setattr(main, "MEMORY_ALERT_NAMES", ["HighMemory"])
    monkeypatch.setattr(main, "STOP_SANDBOXES", True)
    test_client, fake = client
    stop = RecordedStop()
    monkeypatch.setattr(main, "_stop_request", stop)

    response = test_client.post(
        "/alerts", json=_memory_alert_payload(status="resolved")
    )

    assert response.status_code == 200
    assert stop.calls == []
    assert fake.stale_queries == []


def test_memory_alert_stop_network_error_continues(monkeypatch, client, caplog):
    """A stop call raising a network error counts as failed; the rest of
    the stops and the ingestion itself keep going."""
    monkeypatch.setattr(main, "MEMORY_ALERT_NAMES", ["HighMemory"])
    monkeypatch.setattr(main, "STOP_SANDBOXES", True)
    monkeypatch.setattr(main, "STOP_URL", "http://stop:8000/claw-catalog/stop")
    monkeypatch.setattr(main, "STOP_SLUG", "v20260427")
    monkeypatch.setattr(main, "STOP_LIMIT", 10)
    test_client, fake = client
    now = datetime.now(timezone.utc)
    _seed(fake, "sb-a", "10.0.0.1", user_id="u-1",
          request_time=now - timedelta(days=30))
    _seed(fake, "sb-b", "10.0.0.1", user_id="u-2",
          request_time=now - timedelta(days=20))
    stop = RecordedStop(statuses=[HTTPError(None, None, "connection refused", None, None), 200])
    monkeypatch.setattr(main, "_stop_request", stop)

    with caplog.at_level("WARNING", logger="audit-webhook"):
        response = test_client.post("/alerts", json=_memory_alert_payload())

    assert response.status_code == 200
    assert len(stop.calls) == 2
    host_entry = response.json()["stale_users"][0]
    assert host_entry["stopped"] == 1
    assert host_entry["failed"] == 1
    assert "stop request failed" in caplog.text
