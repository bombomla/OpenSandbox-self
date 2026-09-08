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

Run:
    cp audit.toml.example audit.toml   # then edit settings
    python main.py
"""

import asyncio
import logging
import secrets
import sys
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Annotated, Union

# The config/k8s helpers live in ./utils - add it to sys.path so the module
# works when run directly (python main.py) and under pytest.
sys.path.insert(0, str(Path(__file__).resolve().parent / "utils"))

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from psycopg_pool import ConnectionPool
from pydantic import BaseModel, Field

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
# Authentication
# ---------------------------------------------------------------------------

def _valid_session(token: str | None) -> bool:
    return valid_session(UI_PASSWORD, token)


def _session_token(request: Request) -> str | None:
    return session_token_from(request.cookies)


def _login_redirect() -> RedirectResponse:
    return RedirectResponse("/login", status_code=303)


def _require_api_auth(request: Request) -> None:
    if UI_PASSWORD and not _valid_session(_session_token(request)):
        raise HTTPException(status_code=401, detail="login required")


@app.get("/login", response_class=HTMLResponse, include_in_schema=False)
def login_page() -> FileResponse:
    return FileResponse(_STATIC_DIR / "login.html")


@app.post("/login")
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


@app.post("/logout")
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


@app.post("/events", response_model=AuditEventAccepted)
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


@app.get("/status.ok")
def healthz() -> dict:
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Query APIs (auth required when server.ui_password is set)
# ---------------------------------------------------------------------------

@app.get("/api/sandboxes")
def list_sandboxes(
    request: Request,
    store: StoreDep,
    search: Annotated[str | None, Query(min_length=1)] = None,
    sort: Annotated[
        str, Query(pattern=r"^-?(request_time|request_count|accessed|created_at)$")
    ] = "-request_time",
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    time_from: Annotated[datetime | None, Query()] = None,
    time_to: Annotated[datetime | None, Query()] = None,
) -> dict:
    """List per-user/per-sandbox summary groups.

    Rows are grouped by ``user_id`` when the cluster sync resolved one;
    sandboxes without a user id report per-sandbox stats. All of a
    user's sandboxes share one summed ``request_count`` and the latest
    ``request_time`` (see ``store.list_latest``).
    """
    _require_api_auth(request)
    return _safe_query(
        lambda: store.list_latest(
            search=search,
            sort=sort,
            limit=limit,
            offset=offset,
            time_from=time_from,
            time_to=time_to,
        )
    )


@app.get("/api/requests")
def list_requests(
    request: Request,
    store: StoreDep,
    sandbox_id: Annotated[str | None, Query(min_length=1)] = None,
    user_id: Annotated[str | None, Query(min_length=1)] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> dict:
    """List access request details, newest first, filterable by sandbox id
    or by user id (all of the user's sandboxes)."""
    _require_api_auth(request)
    return _safe_query(
        lambda: store.list_details(
            sandbox_id=sandbox_id,
            user_id=user_id,
            limit=limit,
            offset=offset,
        )
    )


@app.post("/api/sync-deleted")
def sync_deleted(request: Request, store: StoreDep) -> dict:
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
    _require_api_auth(request)
    if not K8S_NAMESPACE:
        raise HTTPException(
            status_code=400,
            detail="kubernetes.namespace is not configured",
        )
    k8s_client: k8s.K8sClient = getattr(
        request.app.state, "k8s_client", None
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

@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def index(request: Request):
    """Serve the per-sandbox summary page."""
    if UI_PASSWORD and not _valid_session(_session_token(request)):
        return _login_redirect()
    return FileResponse(_STATIC_DIR / "index.html")


@app.get("/details", response_class=HTMLResponse, include_in_schema=False)
def details(request: Request):
    """Serve the request details page."""
    if UI_PASSWORD and not _valid_session(_session_token(request)):
        return _login_redirect()
    return FileResponse(_STATIC_DIR / "details.html")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=HOST, port=PORT)
