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

"""Sandbox access audit webhook (entry point).

Receives audit events POSTed by the OpenSandbox ingress
(``--audit-enabled --audit-webhook-url ...``) and records them to
PostgreSQL via ``store.py``. Cluster sync lives in ``utils/sync.py``,
session auth in ``utils/auth.py``.

Web UI (password protected when ``server.ui_password`` is set):
- ``GET /``          - per-sandbox latest requests (summary page)
- ``GET /details``   - request details page, filterable by sandbox id
- ``GET /login``     - login page

Alertmanager webhooks (``POST /alerts``): each notification's alerts are
appended to the ``alertmanager_alert`` table (queryable via
``GET /api/alerts``). A firing alert whose alertname is listed in
``[alerts] memory_alert_names`` also triggers a stale-user lookup for
its host (the ``instance`` label, ``IP:port``): users whose sandboxes
on that host were not accessed for more than ``[alerts] stale_days``
days (VIP/whitelisted users excluded) are logged and returned in the
response. When ``[alerts] stop_sandboxes`` is enabled, the first
``[alerts] stop_limit`` (most stale) users' sandbox services are in
addition stopped by POSTing to ``[alerts] stop_url`` (counted in the
response as ``stopped`` / ``failed``). Delivery auth is a Bearer token
from ``[alerts] auth_token`` - required when set, open when empty.

Run:
    cp audit.toml.example audit.toml   # then edit settings
    python main.py
"""

import asyncio
import json
import logging
import secrets
import sys
import urllib.request
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Literal, Union

# The config/k8s helpers live in ./utils - add it to sys.path so the module
# works when run directly (python main.py) and under pytest.
sys.path.insert(0, str(Path(__file__).resolve().parent / "utils"))

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from psycopg_pool import ConnectionPool
from pydantic import BaseModel, ConfigDict, Field

import k8s
from auth import (
    SESSION_COOKIE as _SESSION_COOKIE,
    LoginRequest,
    create_session_token,
    session_token_from,
    valid_session,
)
from config import load_config
from store import AuditStore
from sync import sync_sandboxes as _sync_sandboxes

# Settings come from audit.toml (see audit.toml.example); the config file
# location can be overridden with the AUDIT_CONFIG_PATH env var.
_config = load_config()

logger = logging.getLogger("audit-webhook")
logging.basicConfig(
    level=_config["log_level"].upper(),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)

DATABASE_URL = _config["database_url"]
DB_POOL_MIN = _config["db_pool_min"]
DB_POOL_MAX = _config["db_pool_max"]
HOST = _config["host"]
PORT = _config["port"]

# When non-empty, the web UI and query APIs require login with this password.
# Event ingestion (POST /events) is never password protected - the ingress
# must be able to deliver events without a session.
UI_PASSWORD = _config["ui_password"]

# Kubernetes liveness sync: kubeconfig file path (empty = default kubeconfig,
# falling back to in-cluster credentials) and the namespace whose
# batchsandboxes.sandbox.opensandbox.io resources mark live sandbox ids
# (the resource name is the sandbox id). sync_interval (seconds) enables a
# periodic background sync; 0 means sync only via POST /api/sync-deleted.
# Each sync discovers sandboxes that exist in the cluster but not in the
# database (inserted as never-accessed rows), refreshes each sandbox
# pod's node IP, and reconciles the deleted flags.
KUBECONFIG_PATH = _config["kubeconfig"]
K8S_NAMESPACE = _config["k8s_namespace"]
K8S_SYNC_INTERVAL = _config["k8s_sync_interval"]

# Whitelisted user ids (``[whitelist] users`` in audit.toml): shown on
# the summary page and excluded from GET /api/sandboxes/times. It does
# not change access control or what gets recorded - every sandbox is
# audited alike.
WHITELIST_USERS = _config["whitelist_users"]

# Bearer token for the Alertmanager webhook (``[alerts] auth_token`` in
# audit.toml). When non-empty, POST /alerts requires
# ``Authorization: Bearer <token>`` - Alertmanager sends it via the
# receiver's http_config. When empty, the endpoint is open like
# POST /events (the token is a machine credential, separate from the
# UI password).
ALERT_AUTH_TOKEN = _config["alert_auth_token"]

# Memory-alert stale-user lookup (``[alerts] memory_alert_names``). A
# firing alert whose alertname is listed here looks up the users whose
# sandboxes on the alert's host (the ``instance`` label, ``IP:port`` -
# the port is stripped) were not accessed for more than ``stale_days``
# days (VIP/whitelisted users excluded). The list is logged and returned
# in the POST /alerts response for downstream automation. Empty list =
# the lookup is off.
MEMORY_ALERT_NAMES = _config["memory_alert_names"]
STALE_DAYS = _config["stale_days"]

# Auto-stop on memory alerts (``[alerts] stop_sandboxes`` etc.). When
# enabled, a firing memory alert whose stale-user lookup found users
# POSTs ``{"external_user_id": <user_id>, "slug": stop_slug}`` to
# ``stop_url`` for the first ``stop_limit`` (most stale) users - the
# claw-catalog stop endpoint tears down their sandbox service.
STOP_SANDBOXES = _config["stop_sandboxes"]
STOP_URL = _config["stop_url"]
STOP_SLUG = _config["stop_slug"]
STOP_LIMIT = _config["stop_limit"]

_SESSION_TTL = 7 * 24 * 3600  # 7 days, in seconds

_STATIC_DIR = Path(__file__).resolve().parent / "static"

# Matches the ingress AuditEvent JSON payload (pkg/proxy/audit.go).
class AuditEvent(BaseModel):
    sandbox_id: str = Field(min_length=1)
    uri: str
    method: str
    target: str
    request_time: datetime


class AuditEventAccepted(BaseModel):
    accepted: int


# Matches the Alertmanager webhook notification payload (version 4;
# camelCase keys as sent by Alertmanager, snake_case accepted too via
# populate_by_name). Unknown fields are ignored so new Alertmanager
# versions do not break ingestion.
class AlertmanagerAlert(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    status: str = "firing"
    labels: dict[str, str] = Field(default_factory=dict)
    annotations: dict[str, str] = Field(default_factory=dict)
    starts_at: datetime | None = Field(default=None, alias="startsAt")
    ends_at: datetime | None = Field(default=None, alias="endsAt")
    generator_url: str | None = Field(default=None, alias="generatorURL")
    fingerprint: str = ""


class AlertmanagerPayload(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    version: str | None = None
    group_key: str | None = Field(default=None, alias="groupKey")
    truncated_alerts: int = Field(default=0, alias="truncatedAlerts")
    status: str | None = None
    receiver: str | None = None
    group_labels: dict[str, str] = Field(default_factory=dict, alias="groupLabels")
    common_labels: dict[str, str] = Field(default_factory=dict, alias="commonLabels")
    common_annotations: dict[str, str] = Field(default_factory=dict, alias="commonAnnotations")
    external_url: str | None = Field(default=None, alias="externalURL")
    alerts: list[AlertmanagerAlert] = Field(default_factory=list)


# A stale user flagged by a host memory alert: their user id, their
# current sandbox on the host, the group's effective last access time
# (see AuditStore.list_stale_users) and whole days since then.
class StaleUser(BaseModel):
    user_id: str
    sandbox_id: str
    last_access: str | None = None
    days: int | None = None


# The lookup result for one alerting host (host IP, the alertname that
# flagged it, the stale users found there) plus the auto-stop outcome:
# how many of the first stop_limit users' services the stop endpoint
# reported stopped, and how many calls failed (stopped + failed = the
# number of stop calls made; 0 when auto-stop is off).
class HostStaleUsers(BaseModel):
    host: str
    alertname: str
    users: list[StaleUser]
    stopped: int = 0
    failed: int = 0


class AlertsAccepted(BaseModel):
    accepted: int
    stale_users: list[HostStaleUsers] | None = None


@asynccontextmanager
async def lifespan(_: FastAPI):
    pool = ConnectionPool(
        conninfo=DATABASE_URL,
        min_size=DB_POOL_MIN,
        max_size=DB_POOL_MAX,
        open=True,
    )
    store = AuditStore(pool)
    try:
        store.init_schema()
    except Exception:
        logger.exception("failed to initialize audit schema")
        pool.close()
        raise

    app.state.store = store
    app.state.k8s_client = k8s.K8sClient(KUBECONFIG_PATH)

    sync_task = None
    if K8S_SYNC_INTERVAL > 0:
        if K8S_NAMESPACE:
            sync_task = asyncio.create_task(_periodic_sync(store))
        else:
            logger.warning(
                "kubernetes.sync_interval is set but kubernetes.namespace is not; "
                "periodic deleted-sync disabled"
            )

    logger.info("audit webhook ready on %s:%s (ui auth %s)", HOST, PORT, "on" if UI_PASSWORD else "off")
    try:
        yield
    finally:
        if sync_task is not None:
            sync_task.cancel()
        pool.close()
        logger.info("audit webhook stopped")


async def _periodic_sync(store: AuditStore) -> None:
    """Sync sandboxes against the cluster on a fixed interval; failures only log.

    The sync does blocking k8s/DB calls (each potentially a slow network
    round trip) - run them in a worker thread so the event loop keeps
    serving requests while a sync is in flight.
    """
    while True:
        try:
            result = await asyncio.to_thread(
                _sync_sandboxes, store, app.state.k8s_client, K8S_NAMESPACE
            )
            logger.info("periodic sync: %s", result)
        except Exception:
            logger.exception("periodic sandbox sync failed")
        await asyncio.sleep(K8S_SYNC_INTERVAL)


app = FastAPI(
    title="OpenSandbox Audit Webhook",
    description="Records sandbox access audit events from the ingress to PostgreSQL.",
    version="0.1.0",
    lifespan=lifespan,
)

app.mount("/static", StaticFiles(directory=_STATIC_DIR), name="static")


# ---------------------------------------------------------------------------
# Authentication (unified)
#
# One dependency per protection level. Every protected endpoint declares
# exactly one of them on its route (``dependencies=[Depends(...)]``) -
# new endpoints must use these instead of hand-rolled checks:
#
#   require_page_session          UI pages: session cookie; a missing
#                                 session 303-redirects to /login
#   require_session               UI query APIs: session cookie; 401
#   require_session_or_password   query APIs that also serve programmatic
#                                 callers: session cookie OR
#                                 Authorization: Bearer <ui_password>
#   require_alert_token           machine ingestion (Alertmanager
#                                 POST /alerts): open unless
#                                 [alerts] auth_token is set, then
#                                 Authorization: Bearer <that token>
#
# Each check is a no-op while its credential is unset (server.ui_password
# / [alerts] auth_token empty) - auth is strictly opt-in per surface.
# Event ingestion (POST /events, POST /) stays open by design: the
# ingress delivers without credentials.
# ---------------------------------------------------------------------------


def _session_ok(request: Request) -> bool:
    """A valid UI session cookie for the configured password."""
    return valid_session(UI_PASSWORD, session_token_from(request.cookies))


def _bearer_ok(request: Request, token: str) -> bool:
    """An ``Authorization: Bearer <token>`` header carrying exactly
    ``token`` (constant-time comparison)."""
    scheme, _, value = request.headers.get("authorization", "").partition(" ")
    return scheme.lower() == "bearer" and secrets.compare_digest(
        value.encode(), token.encode()
    )


def require_page_session(request: Request) -> None:
    """UI pages: redirect to /login without a valid session."""
    if UI_PASSWORD and not _session_ok(request):
        raise HTTPException(status_code=303, headers={"Location": "/login"})


def require_session(request: Request) -> None:
    """UI query APIs: reject with 401 without a valid session cookie."""
    if UI_PASSWORD and not _session_ok(request):
        raise HTTPException(status_code=401, detail="login required")


def require_session_or_password(request: Request) -> None:
    """Query APIs that also serve programmatic callers: accept a session
    cookie or an ``Authorization: Bearer <password>`` header carrying
    the UI password directly instead of logging in for a cookie first."""
    if UI_PASSWORD == "":
        return  # auth disabled
    if _session_ok(request) or _bearer_ok(request, UI_PASSWORD):
        return
    raise HTTPException(
        status_code=401,
        detail="login required",
        headers={"WWW-Authenticate": "Bearer"},
    )


def require_alert_token(request: Request) -> None:
    """Machine ingestion (Alertmanager webhook): open unless
    ``[alerts] auth_token`` is set, in which case an
    ``Authorization: Bearer <token>`` header is required (Alertmanager
    sends it via the receiver's http_config)."""
    if ALERT_AUTH_TOKEN == "":
        return  # token auth disabled
    if _bearer_ok(request, ALERT_AUTH_TOKEN):
        return
    raise HTTPException(
        status_code=401,
        detail="invalid or missing bearer token",
        headers={"WWW-Authenticate": "Bearer"},
    )


@app.get("/login", response_class=HTMLResponse, include_in_schema=False)
def login_page() -> FileResponse:
    return FileResponse(_STATIC_DIR / "login.html")


@app.post("/login", tags=["Auth"])
def login(body: LoginRequest, request: Request) -> JSONResponse:
    """Verify the password and issue a session cookie."""
    if UI_PASSWORD == "":
        return JSONResponse({"ok": True})  # auth disabled: nothing to do
    if not secrets.compare_digest(body.password.encode(), UI_PASSWORD.encode()):
        raise HTTPException(status_code=401, detail="密码错误")
    response = JSONResponse({"ok": True})
    response.set_cookie(
        _SESSION_COOKIE,
        create_session_token(UI_PASSWORD, _SESSION_TTL),
        max_age=_SESSION_TTL,
        httponly=True,
        samesite="lax",
    )
    return response


@app.post("/logout", tags=["Auth"])
def logout() -> JSONResponse:
    response = JSONResponse({"ok": True})
    response.delete_cookie(_SESSION_COOKIE)
    return response


# ---------------------------------------------------------------------------
# Event ingestion (ingress -> webhook, no auth)
# ---------------------------------------------------------------------------

def get_store(request: Request) -> AuditStore:
    store: AuditStore | None = getattr(request.app.state, "store", None)
    if store is None:
        raise HTTPException(status_code=503, detail="audit store not ready")
    return store


StoreDep = Annotated[AuditStore, Depends(get_store)]


@app.post("/events", response_model=AuditEventAccepted, tags=["Events"])
@app.post("/", response_model=AuditEventAccepted, include_in_schema=False)
def record_events(
    events: Union[AuditEvent, list[AuditEvent]],
    store: StoreDep,
) -> AuditEventAccepted:
    """Accept a single audit event or a batch of events.

    ``POST /`` is accepted as an alias for ``POST /events`` so a webhook
    URL configured without the path still works.

    Requests whose URI ends with any suffix from
    ``[events] excluded_uri_suffixes`` (case-insensitive, default
    ``["ping"]`` - e.g. `/<sandbox-id>/<port>/ping` health checks) are
    dropped and not recorded to the database.

    For URIs with a query string, only the parameter names are matched -
    values are ignored - so one entry ``/usage?days=`` covers every
    ``/usage?days=<any value>``.
    """
    if not isinstance(events, list):
        events = [events]
    events = [event for event in events if _should_record(event)]
    if not events:
        return AuditEventAccepted(accepted=0)
    try:
        accepted = store.record([event.model_dump() for event in events])
    except Exception:
        logger.exception("failed to record audit events")
        raise HTTPException(status_code=502, detail="failed to record audit events")
    return AuditEventAccepted(accepted=accepted)


# Requests whose URI ends with any of these suffixes (case-insensitive) are
# not recorded - typically liveness/health-check pings, e.g.
# /610c205a-272e-425f-85bf-b27cae2d9ee3/44772/ping. Configurable via the
# [events] excluded_uri_suffixes key in audit.toml.
#
# An entry may carry query parameter names (e.g. ``/usage?days=``): it
# then matches any URI whose path ends with the entry's path part and
# whose query parameter names match - values are ignored, so one entry
# covers ``/usage?days=1``, ``/usage?days=30`` and ``/usage?days=1&x=2``.
_EXCLUDED_URI_SUFFIXES = tuple(
    suffix.lower() for suffix in _config["excluded_uri_suffixes"]
)


def _query_names(uri: str) -> tuple[str, tuple[str, ...]]:
    """Split a URI into its lowercased path and its query parameter names.

    ``/Usage?Days=2&fmt=json`` -> ``("/usage", ("days", "fmt"))``.
    """
    path, _, query = uri.partition("?")
    names = tuple(
        part.partition("=")[0].lower()
        for part in query.split("&")
        if part and part.partition("=")[0]
    )
    return path.lower(), names


def _should_record(event: AuditEvent) -> bool:
    path, names = _query_names(event.uri)
    for suffix in _EXCLUDED_URI_SUFFIXES:
        suffix_path, _, suffix_query = suffix.partition("?")
        if not suffix_query:
            # Plain path suffix match.
            if path.endswith(suffix_path):
                return False
        else:
            # Path suffix + query parameter names (values ignored).
            suffix_names = tuple(
                name.rstrip("=")
                for name in suffix_query.split("&")
                if name.rstrip("=")
            )
            if (
                path.endswith(suffix_path)
                and names
                and all(name in names for name in suffix_names)
            ):
                return False
    return True


@app.post(
    "/alerts",
    response_model=AlertsAccepted,
    response_model_exclude_none=True,
    dependencies=[Depends(require_alert_token)],
    tags=["Alerts"],
)
def record_alerts(
    payload: AlertmanagerPayload,
    store: StoreDep,
) -> AlertsAccepted:
    """Receive an Alertmanager webhook notification.

    Each alert in the notification is appended to the
    ``alertmanager_alert`` table as delivered (a later ``resolved``
    notification adds a row; it does not rewrite the ``firing`` one).
    Timestamps are truncated to whole seconds; Alertmanager's zero
    ``endsAt`` (``0001-01-01T00:00:00Z``, meaning "still firing") is
    stored as NULL.

    Stale-user lookup: a firing alert whose alertname is listed in
    ``[alerts] memory_alert_names`` identifies its host via the
    ``instance`` label (``IP:port``) and lists the users whose sandboxes
    on that host were not accessed for more than ``[alerts]
    stale_days`` days (VIP/whitelisted users excluded) - logged as a
    warning and attached to the response as ``stale_users`` (omitted
    when nothing matched). Auto-stop: when ``[alerts] stop_sandboxes``
    is enabled, the first ``[alerts] stop_limit`` users of each host are
    additionally stopped via ``[alerts] stop_url`` and the result is
    counted on the host entry (``stopped`` / ``failed``). The lookup
    never fails the delivery: Alertmanager must not retry and duplicate
    the stored alerts.

    Authentication: none when ``[alerts] auth_token`` is empty;
    otherwise an ``Authorization: Bearer <token>`` header carrying that
    token is required (configure the same token in the Alertmanager
    receiver's http_config). The UI password never applies here.
    """
    if payload.truncated_alerts:
        logger.warning(
            "alertmanager truncated %s alerts in this notification",
            payload.truncated_alerts,
        )
    if not payload.alerts:
        return AlertsAccepted(accepted=0)
    # The receiver/group key live on the notification envelope; repeat
    # them on every alert row so each row is self-contained.
    envelope = {"receiver": payload.receiver, "group_key": payload.group_key}
    try:
        accepted = store.record_alerts(
            [alert.model_dump() | envelope for alert in payload.alerts]
        )
    except Exception:
        logger.exception("failed to record alerts")
        raise HTTPException(status_code=502, detail="failed to record alerts")
    return AlertsAccepted(
        accepted=accepted, stale_users=_stale_users_for(store, payload.alerts)
    )


def _host_ip(instance: str) -> str:
    """Strip the ``:port`` from an Alertmanager ``instance`` label
    (node_exporter style ``10.0.0.1:9100``); a value without a numeric
    port suffix stays as-is (``pod-1``, bare ``10.0.0.1``)."""
    head, _, tail = instance.rpartition(":")
    return head if head and tail.isdigit() else instance


def _days_since(last_access: str | None) -> int | None:
    """Whole days since an ISO timestamp (None when there is none)."""
    if last_access is None:
        return None
    return (datetime.now(timezone.utc) - datetime.fromisoformat(last_access)).days


def _stop_request(url: str, body: dict) -> int:
    """POST one stop call to the claw-catalog stop endpoint; returns the
    HTTP status code. Kept module-level so tests can monkeypatch it."""
    request = urllib.request.Request(
        url,
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        return response.status


def _stop_sandboxes(users: list[dict]) -> tuple[int, int]:
    """Stop the first ``stop_limit`` stale users' sandbox services.

    Each stop is one POST to ``[alerts] stop_url`` with the user id as
    ``external_user_id`` and ``[alerts] stop_slug`` as ``slug``. Calls run
    synchronously, one after another; a failed call (non-2xx status or
    network error) is logged and counted without stopping the rest. Only
    runs when ``[alerts] stop_sandboxes`` is enabled; returns
    ``(stopped, failed)``.
    """
    if not STOP_SANDBOXES or not STOP_URL:
        return (0, 0)
    stopped = failed = 0
    for user in users[:STOP_LIMIT]:
        body = {"external_user_id": user["user_id"], "slug": STOP_SLUG}
        try:
            status = _stop_request(STOP_URL, body)
        except Exception:
            failed += 1
            logger.warning(
                "stop request failed for user %s (sandbox %s)",
                user["user_id"],
                user["sandbox_id"],
            )
            continue
        if 200 <= status < 300:
            stopped += 1
            logger.info("stopped user %s (sandbox %s)", user["user_id"], user["sandbox_id"])
        else:
            failed += 1
            logger.warning(
                "stop request for user %s (sandbox %s) returned HTTP %s",
                user["user_id"],
                user["sandbox_id"],
                status,
            )
    return (stopped, failed)


def _stale_users_for(
    store: AuditStore, alerts: list[AlertmanagerAlert]
) -> list[HostStaleUsers] | None:
    """Stale users per host flagged by the firing memory alerts of a
    notification.

    Hosts are deduplicated (one query per host; the first alertname that
    flagged it is reported). A memory alert without an ``instance``
    label names no host and is skipped with a warning. Lookup failures
    are logged and skipped - they must not fail the ingestion, or
    Alertmanager would retry the notification and duplicate the stored
    alerts.
    """
    hosts: dict[str, str] = {}
    for alert in alerts:
        if alert.status != "firing":
            continue
        if alert.labels.get("alertname") not in MEMORY_ALERT_NAMES:
            continue
        instance = alert.labels.get("instance")
        if not instance:
            logger.warning(
                "%s alert %s carries no instance label; host lookup skipped",
                alert.labels.get("alertname"),
                alert.fingerprint,
            )
            continue
        hosts.setdefault(_host_ip(instance), alert.labels["alertname"])
    results: list[HostStaleUsers] = []
    for host, alertname in hosts.items():
        try:
            users = store.list_stale_users(host, STALE_DAYS, WHITELIST_USERS)
        except Exception:
            logger.exception("failed to look up stale users on host %s", host)
            continue
        if not users:
            logger.info(
                "%s alert on host %s: no users stale for >%s days",
                alertname,
                host,
                STALE_DAYS,
            )
            continue
        logger.warning(
            "%s alert on host %s: %d user(s) not accessed for >%s days"
            " (VIP excluded): %s",
            alertname,
            host,
            len(users),
            STALE_DAYS,
            "; ".join(
                "%s (sandbox %s, last access %s)"
                % (
                    user["user_id"],
                    user["sandbox_id"],
                    user["last_access"] or "never recorded",
                )
                for user in users
            ),
        )
        stopped, failed = _stop_sandboxes(users)
        results.append(
            HostStaleUsers(
                host=host,
                alertname=alertname,
                users=[
                    StaleUser(days=_days_since(user["last_access"]), **user)
                    for user in users
                ],
                stopped=stopped,
                failed=failed,
            )
        )
    return results or None


@app.get("/status.ok", tags=["System"])
def healthz() -> dict:
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Query APIs (auth required when server.ui_password is set)
# ---------------------------------------------------------------------------

@app.get("/api/sandboxes", dependencies=[Depends(require_session)], tags=["Query"])
def list_sandboxes(
    store: StoreDep,
    search: Annotated[str | None, Query(min_length=1)] = None,
    sort: Annotated[
        str,
        Query(
            pattern=r"^-?(request_time|request_count|accessed|created_at|user_type)$"
        ),
    ] = "-request_time",
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    time_from: Annotated[datetime | None, Query()] = None,
    time_to: Annotated[datetime | None, Query()] = None,
    user_type: Annotated[Literal["vip", "normal"] | None, Query()] = None,
) -> dict:
    """List per-user/per-sandbox summary groups.

    Rows are grouped by ``user_id`` when the cluster sync resolved one;
    sandboxes without a user id report per-sandbox stats. All of a
    user's sandboxes share one summed ``request_count`` and the latest
    ``request_time`` (see ``store.list_latest``). When the user's
    current sandbox was never accessed (``未访问``), the group's
    ``request_time`` falls back to the latest request of the user's
    already-deleted sandboxes, so the latest-request column still
    shows when the user was last active; ``time_from``/``time_to``
    bind that effective time.

    ``user_type=vip`` keeps whitelisted users (``[whitelist] users``),
    ``user_type=normal`` the rest; ``sort=user_type`` /
    ``-user_type`` orders by the same membership (ascending = normal
    users first, descending = VIP first).
    """
    return _safe_query(
        lambda: store.list_latest(
            search=search,
            sort=sort,
            limit=limit,
            offset=offset,
            time_from=time_from,
            time_to=time_to,
            whitelist_users=WHITELIST_USERS,
            user_type=user_type,
        )
    )


@app.get(
    "/api/sandboxes/times",
    dependencies=[Depends(require_session_or_password)],
    tags=["Query"],
)
def list_sandbox_times(
    store: StoreDep,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> dict:
    """List one row per sandbox id: ``user_id``, ``sandbox_id``,
    ``created_at`` and ``request_time`` (the latest request time),
    newest first.

    Sandboxes that were never accessed have no latest request time -
    their ``request_time`` falls back to the creation time, so no row
    carries an empty ``request_time``. Deleted sandboxes are included
    (their audit history stays complete).

    Whitelisted users (``[whitelist] users`` in audit.toml) are
    excluded - their sandboxes stay out of this usage/lifetime report
    (sandboxes without a user id are still listed).

    Authentication: a session cookie (login) or an
    ``Authorization: Bearer <password>`` header carrying the UI
    password (``server.ui_password``).
    """
    return _safe_query(
        lambda: store.list_sandbox_times(
            limit=limit,
            offset=offset,
            exclude_users=WHITELIST_USERS,
        )
    )


@app.get(
    "/api/host-sandboxes",
    dependencies=[Depends(require_session_or_password)],
    tags=["Query"],
)
def list_host_sandboxes(
    store: StoreDep,
    node_ip: Annotated[str, Query(min_length=1)],
    stale_days: Annotated[int | None, Query(ge=1)] = None,
) -> dict:
    """List the live sandboxes on a host (node IP), one row each:
    ``user_id``, ``sandbox_id``, ``created_at`` and ``request_time``
    (the latest request time; ``null`` when the sandbox was never
    accessed), least-recently-active first.

    ``node_ip`` is the host IP of the node whose sandboxes are listed;
    an Alertmanager-style ``instance`` label (``IP:port``) is accepted -
    the ``:port`` is stripped. Deleted sandboxes are excluded (only live
    sandboxes sit on a host); their audit history stays on
    ``GET /api/requests``.

    Optional ``stale_days`` keeps only sandboxes whose effective
    last-active time - the latest request time, or the creation time when
    the sandbox was never accessed - is older than that many days. A
    sandbox with no timestamp at all counts as stale. Without it, every
    live sandbox on the host is returned.

    Authentication: a session cookie (login) or an
    ``Authorization: Bearer <password>`` header carrying the UI
    password (``server.ui_password``).
    """
    return _safe_query(
        lambda: store.list_host_sandboxes(
            node_ip=_host_ip(node_ip),
            stale_days=stale_days,
        )
    )


@app.get("/api/requests", dependencies=[Depends(require_session)], tags=["Query"])
def list_requests(
    store: StoreDep,
    sandbox_id: Annotated[str | None, Query(min_length=1)] = None,
    user_id: Annotated[str | None, Query(min_length=1)] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> dict:
    """List access request details, newest first, filterable by sandbox id
    or by user id (all of the user's sandboxes)."""
    return _safe_query(
        lambda: store.list_details(
            sandbox_id=sandbox_id,
            user_id=user_id,
            limit=limit,
            offset=offset,
        )
    )


@app.get("/api/alerts", dependencies=[Depends(require_session)], tags=["Alerts"])
def list_alerts(
    store: StoreDep,
    status: Literal["firing", "resolved"] | None = None,
    search: Annotated[str | None, Query(min_length=1)] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> dict:
    """List alerts received from Alertmanager, newest delivery first.

    ``status`` keeps only firing or resolved alerts; ``search``
    fuzzy-matches fingerprints, receivers, group keys and the JSON text
    of labels/annotations (alertname, instance, severity, summary etc.
    all hit with one field).
    """
    return _safe_query(
        lambda: store.list_alerts(
            status=status,
            search=search,
            limit=limit,
            offset=offset,
        )
    )


@app.get("/api/whitelist", dependencies=[Depends(require_session)], tags=["Query"])
def get_whitelist() -> dict:
    """List the whitelisted user ids (``[whitelist] users`` in audit.toml).

    The whitelist is informational only - it marks notable users on the
    summary page and does not change what is recorded or who may access
    the UI.
    """
    return {"users": list(WHITELIST_USERS)}


@app.post("/api/sync-deleted", dependencies=[Depends(require_session)], tags=["System"])
def sync_deleted(store: StoreDep) -> dict:
    """Sync the summary table against the cluster.

    Sandboxes whose BatchSandbox resource exists in the namespace
    (``kubernetes.namespace``, via the kubeconfig at
    ``kubernetes.kubeconfig``) but has no database row are inserted as
    never-accessed rows (``accessed = FALSE``, ``created_at`` = the
    resource's creationTimestamp, shown in the UI with an ``未访问``
    marker); existing rows missing a creation timestamp get it
    backfilled. Each sandbox pod's node IP is refreshed into
    ``node_ip``. Then the ``deleted`` flags are reconciled: summary rows
    whose sandbox id is not among the live resource names (the resource
    name is the sandbox id) are marked ``deleted`` (shown with a ``已删除``
    marker in the UI); previously deleted ids that reappear are restored.
    """
    if not K8S_NAMESPACE:
        raise HTTPException(
            status_code=400,
            detail="kubernetes.namespace is not configured",
        )
    k8s_client: k8s.K8sClient = getattr(
        app.state, "k8s_client", None
    ) or k8s.K8sClient(KUBECONFIG_PATH)
    try:
        result = _sync_sandboxes(store, k8s_client, K8S_NAMESPACE)
    except k8s.K8sError as exc:
        logger.error("k8s sandbox sync failed: %s", exc)
        raise HTTPException(status_code=502, detail=str(exc)) from None
    except Exception:
        logger.exception("failed to sync sandboxes")
        raise HTTPException(status_code=502, detail="failed to sync sandboxes") from None
    return {"namespace": K8S_NAMESPACE, **result}


def _safe_query(query) -> dict:
    try:
        return query()
    except Exception:
        logger.exception("failed to query audit records")
        raise HTTPException(status_code=502, detail="failed to query audit records")


# ---------------------------------------------------------------------------
# Web pages (auth required when server.ui_password is set)
# ---------------------------------------------------------------------------

@app.get(
    "/",
    response_class=HTMLResponse,
    include_in_schema=False,
    dependencies=[Depends(require_page_session)],
)
def index() -> FileResponse:
    """Serve the per-sandbox summary page."""
    return FileResponse(_STATIC_DIR / "index.html")


@app.get(
    "/details",
    response_class=HTMLResponse,
    include_in_schema=False,
    dependencies=[Depends(require_page_session)],
)
def details() -> FileResponse:
    """Serve the request details page."""
    return FileResponse(_STATIC_DIR / "details.html")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=HOST, port=PORT)
