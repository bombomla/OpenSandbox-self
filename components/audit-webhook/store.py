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

"""PostgreSQL storage for sandbox access audit events.

Two tables are maintained:

- ``sandbox_access_log``: one row per received request (request detail).
- ``sandbox_access_latest``: one row per sandbox id, holding the latest
  request and the total request count (summary). Rows whose sandbox
  resource is gone are flagged ``deleted`` and returned with that flag
  (shown as ``已删除`` in the UI) - audit history stays searchable even
  after an ephemeral sandbox is removed from the cluster.
  Sandboxes discovered in the cluster before any request arrived are
  inserted with ``accessed = FALSE`` (request fields NULL) so the UI can
  tell them apart from accessed ones.
"""

import logging
from datetime import datetime, timezone

from psycopg import sql
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

logger = logging.getLogger(__name__)

# One row per access request.
_CREATE_DETAIL_TABLE = """
CREATE TABLE IF NOT EXISTS sandbox_access_log (
    id           BIGSERIAL PRIMARY KEY,
    sandbox_id   TEXT        NOT NULL,
    uri          TEXT        NOT NULL,
    method       TEXT        NOT NULL,
    target       TEXT        NOT NULL,
    request_time TIMESTAMPTZ NOT NULL,
    received_at  TIMESTAMPTZ NOT NULL DEFAULT date_trunc('second', now())
);
CREATE INDEX IF NOT EXISTS idx_sandbox_access_log_sandbox_time
    ON sandbox_access_log (sandbox_id, request_time DESC);
"""

# One row per sandbox id, tracking its latest request and total count.
# ``deleted`` marks sandboxes whose BatchSandbox resource no longer exists
# (synced from Kubernetes); deleted rows are hidden from the UI/API.
# ``accessed`` is FALSE on rows inserted by the cluster discovery for
# sandboxes that have not been accessed yet - their request fields are
# NULL until the first audit event arrives.
# ``created_at`` holds the sandbox's BatchSandbox creationTimestamp on
# discovery-inserted rows; ``node_ip`` is the IP of the node the sandbox
# pod runs on (synced from the cluster); ``user_id`` is the user id from
# the BatchSandbox's claw-data volumeMount subPath (synced likewise).
_CREATE_SUMMARY_TABLE = """
CREATE TABLE IF NOT EXISTS sandbox_access_latest (
    sandbox_id    TEXT        PRIMARY KEY,
    uri           TEXT,
    method        TEXT,
    target        TEXT,
    request_time  TIMESTAMPTZ,
    request_count BIGINT      NOT NULL DEFAULT 1,
    deleted       BOOLEAN     NOT NULL DEFAULT FALSE,
    accessed      BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ,
    node_ip       TEXT,
    user_id       TEXT,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT date_trunc('second', now())
);
"""

# Migrations for tables created before the ``deleted``/``accessed``/
# ``created_at``/``node_ip``/``user_id`` columns existed; the request
# columns must be nullable to hold unaccessed rows.
_ALTER_SUMMARY_MIGRATIONS = """
ALTER TABLE sandbox_access_latest
    ADD COLUMN IF NOT EXISTS deleted BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS accessed BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS node_ip TEXT,
    ADD COLUMN IF NOT EXISTS user_id TEXT;
ALTER TABLE sandbox_access_latest
    ALTER COLUMN uri DROP NOT NULL,
    ALTER COLUMN method DROP NOT NULL,
    ALTER COLUMN target DROP NOT NULL,
    ALTER COLUMN request_time DROP NOT NULL
"""

# Truncate timestamps to whole seconds on write.
_TRUNCATED_NOW = "date_trunc('second', now())"

_INSERT_DETAIL = """
INSERT INTO sandbox_access_log (sandbox_id, uri, method, target, request_time, received_at)
VALUES (%(sandbox_id)s, %(uri)s, %(method)s, %(target)s, %(request_time)s, {now})
""".format(now=_TRUNCATED_NOW)

# Upsert the summary row. The WHERE clause guards against out-of-order
# events: an older event never overwrites a newer summary. A NULL
# request_time (row created by the pod discovery, never accessed) loses
# the comparison, so it is handled explicitly.
_UPSERT_SUMMARY = """
INSERT INTO sandbox_access_latest
    (sandbox_id, uri, method, target, request_time, request_count, accessed, updated_at)
VALUES
    (%(sandbox_id)s, %(uri)s, %(method)s, %(target)s, %(request_time)s, 1, TRUE, {now})
ON CONFLICT (sandbox_id) DO UPDATE SET
    uri           = EXCLUDED.uri,
    method        = EXCLUDED.method,
    target        = EXCLUDED.target,
    request_time  = EXCLUDED.request_time,
    request_count = sandbox_access_latest.request_count + 1,
    accessed      = TRUE,
    updated_at    = {now}
WHERE EXCLUDED.request_time >= sandbox_access_latest.request_time
   OR sandbox_access_latest.request_time IS NULL
""".format(now=_TRUNCATED_NOW)

# Placeholder rows for sandboxes discovered in the cluster before any
# request arrived. Rows that already exist get their ``created_at``/
# ``user_id`` backfilled when still NULL (e.g. the sandbox was accessed
# before the first sync ran) - everything else is left untouched. One
# statement for all ids (the DB may be a high-latency round trip away);
# RETURNING splits inserted vs. backfilled rows (``xmax = 0`` marks
# fresh inserts).
_INSERT_DISCOVERED = """
INSERT INTO sandbox_access_latest
    (sandbox_id, uri, method, target, request_time, request_count, accessed, created_at, user_id, updated_at)
SELECT name, NULL, NULL, NULL, NULL, 0, FALSE, created_at, user_id, {now}
FROM unnest(%(ids)s::text[], %(created)s::timestamptz[], %(users)s::text[])
    AS discovered(name, created_at, user_id)
ON CONFLICT (sandbox_id) DO UPDATE SET
    created_at = EXCLUDED.created_at,
    user_id = COALESCE(
        EXCLUDED.user_id, sandbox_access_latest.user_id
    )
WHERE (sandbox_access_latest.created_at IS NULL
       AND EXCLUDED.created_at IS NOT NULL)
   OR (sandbox_access_latest.user_id IS NULL
       AND EXCLUDED.user_id IS NOT NULL)
RETURNING (xmax = 0) AS inserted
""".format(now=_TRUNCATED_NOW)

# Per-sandbox rows carrying, next to their own summary fields, the latest
# request across ALL rows of their group key - deleted sandboxes included.
# ``history_request_time`` backs the summary fallback: when a user's
# current (non-deleted) sandbox was never accessed (``request_time`` is
# NULL), the group reports the user's latest request from their
# already-removed sandboxes, so the 最新请求时间 column keeps showing
# when the user was last active. Groups keyed by sandbox id (no user_id)
# never hit the fallback - a deleted row cannot coexist with a live row
# of the same sandbox id.
_LATEST_ALL_ROWS = """
    SELECT sandbox_id, request_time, request_count, deleted, accessed, created_at,
           user_id, node_ip,
           COALESCE(user_id, sandbox_id) AS uid,
           max(request_time) OVER (PARTITION BY COALESCE(user_id, sandbox_id)) AS history_request_time
    FROM sandbox_access_latest
"""

# The group's effective latest request time: the current (non-deleted)
# sandbox's latest request, or - when it was never accessed - the latest
# request from the user's deleted sandboxes (see _LATEST_ALL_ROWS). HAVING
# cannot reference SELECT aliases, so the expression is spelled out and
# reused by the time filter below.
_EFF_REQUEST_TIME = "COALESCE(max(request_time), max(history_request_time))"

# Summary listing grouped by user. A user runs at most one sandbox at a
# time, so a non-deleted member set per user is normally exactly one
# row: the listing reports that current sandbox (``sandbox_id``) next
# to the user, with a ``sandbox_count`` fallback for the (unexpected)
# multi-active case. Sandboxes without a user_id fall back to
# per-sandbox stats (uid = sandbox id, user_id NULL). The member CTE
# filters first, so a group is included when any member matches the
# search/user_type filters; the time filters bind the group's effective
# latest request time (deleted-sandbox fallback included) via HAVING.
# Deleted history is hidden here but stays queryable through
# /api/requests (the user filter includes it).
# The window count piggybacks the total on the listing query so a page
# load costs one round trip instead of two; the plain COUNT remains as
# a fallback for pages past the end (no rows returned -> no total known).
_LIST_LATEST = (
    "WITH all_rows AS ("
    + _LATEST_ALL_ROWS
    + """),
member AS (SELECT * FROM all_rows WHERE NOT deleted {extra})
SELECT uid,
       max(user_id) AS user_id,
       max(sandbox_id) AS sandbox_id,
       max(node_ip) AS node_ip,
       count(*) AS sandbox_count,
       bool_and(accessed) AS accessed,
       min(created_at) AS created_at,
       """
    + f"{_EFF_REQUEST_TIME} AS request_time,\n"
    + """       sum(request_count) AS request_count,
       count(*) OVER () AS __total
FROM member
GROUP BY uid
HAVING {having}
ORDER BY {order}
LIMIT %(limit)s OFFSET %(offset)s
"""
)

_COUNT_LATEST = (
    "WITH all_rows AS ("
    + _LATEST_ALL_ROWS
    + """),
member AS (SELECT * FROM all_rows WHERE NOT deleted {extra})
SELECT count(*) AS total FROM (
    SELECT uid FROM member GROUP BY uid HAVING {having}
) AS groups
"""
)

# Whitelisted sort orders for the grouped summary listing. Never-accessed
# rows have a NULL request_time and always sort last within an accessed
# group; groups without a creation timestamp always sort last. The
# user_type orders rank whitelist (VIP) groups via the bound ``whitelist``
# array: descending puts VIP users first, ascending normal users first;
# ties fall back to the latest request time.
_LATEST_ORDERS = {
    "request_time": "request_time ASC",
    "-request_time": "request_time DESC NULLS LAST",
    "request_count": "request_count ASC",
    "-request_count": "request_count DESC",
    "accessed": "accessed ASC, request_time DESC NULLS LAST",
    "-accessed": "accessed DESC, request_time DESC NULLS LAST",
    "created_at": "created_at ASC NULLS LAST",
    "-created_at": "created_at DESC NULLS LAST",
    "user_type": "(uid = ANY(%(whitelist)s)) ASC, request_time DESC NULLS LAST",
    "-user_type": "(uid = ANY(%(whitelist)s)) DESC, request_time DESC NULLS LAST",
}

# Flat per-sandbox listing for usage/lifetime reports: one row per
# sandbox id with its user id, creation time and latest request time.
# Sandboxes never accessed (request_time NULL) report their creation
# time as the latest request time via COALESCE, so every row carries a
# usable "last seen" timestamp. All rows are returned, deleted ones
# included (audit history stays complete even after an ephemeral
# sandbox is removed from the cluster). ``{where}`` optionally drops
# whitelisted users (their rows are excluded from the report).
_LIST_SANDBOX_TIMES = """
SELECT sandbox_id,
       user_id,
       created_at,
       COALESCE(request_time, created_at) AS request_time,
       count(*) OVER () AS __total
FROM sandbox_access_latest
{where}
ORDER BY request_time DESC NULLS LAST
LIMIT %(limit)s OFFSET %(offset)s
"""

_COUNT_SANDBOX_TIMES = """
SELECT count(*) AS total FROM sandbox_access_latest {where}
"""

_LIST_DETAILS = """
SELECT log.id, log.sandbox_id, log.uri, log.method, log.target, log.request_time, log.received_at,
       latest.user_id, latest.deleted AS sandbox_deleted,
       count(*) OVER () AS __total
FROM sandbox_access_log AS log
LEFT JOIN sandbox_access_latest AS latest ON latest.sandbox_id = log.sandbox_id
WHERE {where}
ORDER BY log.id DESC
LIMIT %(limit)s OFFSET %(offset)s
"""

_COUNT_DETAILS = """
SELECT count(*) AS total
FROM sandbox_access_log AS log
WHERE {where}
"""


class AuditStore:
    """Writes audit events to PostgreSQL using a connection pool."""

    def __init__(self, pool: ConnectionPool):
        self.pool = pool

    def init_schema(self) -> None:
        """Create tables and indexes if they do not exist (idempotent)."""
        with self.pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(sql.SQL(_CREATE_DETAIL_TABLE))
                cur.execute(sql.SQL(_CREATE_SUMMARY_TABLE))
                cur.execute(sql.SQL(_ALTER_SUMMARY_MIGRATIONS))
        logger.info("audit schema initialized")

    def record(self, events: list[dict]) -> int:
        """Persist events in a single transaction.

        Each event writes one detail row and upserts the sandbox summary
        row. Returns the number of recorded events.
        """
        if not events:
            return 0

        with self.pool.connection() as conn:
            with conn.cursor() as cur:
                for event in events:
                    params = _normalize(event)
                    cur.execute(_INSERT_DETAIL, params)
                    cur.execute(_UPSERT_SUMMARY, params)
        return len(events)

    def list_latest(
        self,
        search: str | None = None,
        sort: str = "-request_time",
        limit: int = 50,
        offset: int = 0,
        time_from: datetime | None = None,
        time_to: datetime | None = None,
        whitelist_users: list[str] | None = None,
        user_type: str | None = None,
    ) -> dict:
        """List per-user summary groups, sorted by ``sort``.

        A user runs at most one sandbox at a time, so each group
        normally holds one non-deleted sandbox: the row shows the user
        (``user_id``) next to their current sandbox (``sandbox_id``),
        with ``sandbox_count`` > 1 flagging the unexpected multi-active
        case. Sandboxes without a user id report per-sandbox stats with
        ``user_id = NULL``. Rows whose sandbox resource is gone
        (``deleted = TRUE``) are hidden from the listing - the audit
        history of removed ephemeral sandboxes stays queryable through
        ``list_details``. When the user's current sandbox was never
        accessed (``未访问``), the group's ``request_time`` falls back to
        the latest request of the user's deleted sandboxes, so the
        latest-request column still shows when the user was last active.
        ``search`` matches user ids / sandbox ids by substring
        (case-insensitive, fuzzy) OR node IPs exactly - typing an IP
        returns every sandbox on that node (a group is included when
        any member matches). ``time_from``/``time_to`` bind the group's
        effective latest request time, fallback included (inclusive;
        naive timestamps are assumed to be UTC). ``sort`` is a
        whitelisted key from ``_LATEST_ORDERS`` (``-`` prefix means
        descending); default is newest first. The group's ``node_ip``
        is its current sandbox's node (a NULL when the pod is not
        scheduled yet).

        ``whitelist_users`` marks the VIP users (``[whitelist] users``):
        ``user_type = "vip"`` keeps only groups whose key is in it,
        ``"normal"`` keeps the rest (with an empty whitelist, every
        group is normal); it also drives the ``user_type`` sort keys.
        """
        try:
            order = _LATEST_ORDERS[sort]
        except KeyError:
            raise ValueError(f"invalid sort key: {sort}") from None

        params: dict = {
            "limit": limit,
            "offset": offset,
            "whitelist": whitelist_users or [],
        }
        conditions = []
        # Time filters go to HAVING (they bind the group's effective
        # request time, fallback included); search/user_type filter the
        # member rows. HAVING cannot reference SELECT aliases, hence the
        # spelled-out _EFF_REQUEST_TIME expression.
        having = []
        if search:
            # Fuzzy match on the group key (user id or bare sandbox id) OR
            # member sandbox ids OR exact member node_ip; escape LIKE
            # wildcards so user input is matched literally.
            params["pattern"] = f"%{_like_escape(search)}%"
            params["node_ip"] = search
            conditions.append(
                "(COALESCE(user_id, sandbox_id) ILIKE %(pattern)s ESCAPE '\\'"
                " OR sandbox_id ILIKE %(pattern)s ESCAPE '\\'"
                " OR node_ip = %(node_ip)s)"
            )
        if user_type == "vip":
            conditions.append("COALESCE(user_id, sandbox_id) = ANY(%(whitelist)s)")
        elif user_type == "normal":
            # COALESCE never yields NULL (sandbox_id is the primary key),
            # so the NULL-trap of ``<> ALL`` does not apply here.
            conditions.append("COALESCE(user_id, sandbox_id) <> ALL(%(whitelist)s)")
        if time_from is not None:
            params["time_from"] = _ensure_utc(time_from)
            having.append(f"{_EFF_REQUEST_TIME} >= %(time_from)s")
        if time_to is not None:
            params["time_to"] = _ensure_utc(time_to)
            having.append(f"{_EFF_REQUEST_TIME} <= %(time_to)s")
        extra = f" AND {' AND '.join(conditions)}" if conditions else ""
        having_clause = " AND ".join(having) if having else "TRUE"

        with self.pool.connection() as conn:
            conn.row_factory = dict_row
            with conn.cursor() as cur:
                cur.execute(
                    _LIST_LATEST.format(
                        extra=extra, having=having_clause, order=order
                    ),
                    params,
                )
                rows = cur.fetchall()
                if rows:
                    total = rows[0]["__total"]
                    rows = [_drop_total(row) for row in rows]
                else:
                    # Past the last page: the window count returned nothing,
                    # fall back to a separate COUNT for the true total.
                    cur.execute(
                        _COUNT_LATEST.format(extra=extra, having=having_clause),
                        params,
                    )
                    total = cur.fetchone()["total"]
        return {"total": total, "items": [_jsonify(row) for row in rows]}

    def list_sandbox_times(
        self,
        limit: int = 50,
        offset: int = 0,
        exclude_users: list[str] | None = None,
    ) -> dict:
        """List one row per sandbox id: user id, creation time and latest
        request time, newest first.

        The latest request time falls back to the creation time for
        sandboxes that were never accessed (their ``request_time`` is
        NULL), so no row has an empty ``request_time``. Deleted rows are
        included - the audit history of removed ephemeral sandboxes
        stays complete. ``exclude_users`` drops every row of the listed
        user ids (the whitelist: their sandboxes stay out of the
        usage/lifetime report); rows without a user id are kept.
        """
        # Skipping the filter entirely lets the planner use a plain scan.
        # The explicit IS NULL keeps rows without a user id: ``NULL <> ALL
        # (array)`` evaluates to NULL and would drop them otherwise.
        where = ""
        if exclude_users:
            where = (
                "WHERE user_id IS NULL OR user_id <> ALL(%(exclude_users)s)"
            )
            params = {"exclude_users": exclude_users}
        else:
            params = {}
        params.update({"limit": limit, "offset": offset})

        with self.pool.connection() as conn:
            conn.row_factory = dict_row
            with conn.cursor() as cur:
                cur.execute(
                    _LIST_SANDBOX_TIMES.format(where=where),
                    params,
                )
                rows = cur.fetchall()
                if rows:
                    total = rows[0]["__total"]
                    rows = [_drop_total(row) for row in rows]
                else:
                    # Past the last page: the window count returned nothing,
                    # fall back to a separate COUNT for the true total.
                    cur.execute(_COUNT_SANDBOX_TIMES.format(where=where), params)
                    total = cur.fetchone()["total"]
        return {"total": total, "items": [_jsonify(row) for row in rows]}

    def list_details(
        self,
        sandbox_id: str | None = None,
        user_id: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> dict:
        """List access request details, newest first, filterable by sandbox
        or by user id.

        The user filter covers the user's *whole history* - current and
        already-removed (deleted) sandboxes alike - and each row carries
        ``sandbox_deleted`` so the UI can tell them apart.
        """
        # Build the WHERE clause dynamically: psycopg cannot infer the type
        # of a NULL-bound parameter, and skipping the filter entirely lets
        # the query planner use the (sandbox_id, request_time) index.
        # The user filter resolves to all of the user's sandbox ids via
        # the summary table (deleted ones included - history).
        conditions, params = [], {}
        if sandbox_id:
            conditions.append("log.sandbox_id = %(sandbox_id)s")
            params["sandbox_id"] = sandbox_id
        if user_id:
            conditions.append(
                "log.sandbox_id IN (SELECT sandbox_id FROM sandbox_access_latest"
                " WHERE user_id = %(user_id)s)"
            )
            params["user_id"] = user_id
        where = " AND ".join(conditions) if conditions else "TRUE"
        params.update({"limit": limit, "offset": offset})

        with self.pool.connection() as conn:
            conn.row_factory = dict_row
            with conn.cursor() as cur:
                cur.execute(
                    _LIST_DETAILS.format(where=where),
                    params,
                )
                rows = cur.fetchall()
                if rows:
                    total = rows[0]["__total"]
                    rows = [_drop_total(row) for row in rows]
                else:
                    # Past the last page: the window count returned nothing,
                    # fall back to a separate COUNT for the true total.
                    cur.execute(_COUNT_DETAILS.format(where=where), params)
                    total = cur.fetchone()["total"]
        return {"total": total, "items": [_jsonify(row) for row in rows]}

    def upsert_discovered_sandboxes(self, sandboxes: list[dict]) -> dict:
        """Insert placeholder rows for unaccessed sandboxes and backfill
        creation timestamps / user ids.

        ``sandboxes`` are the live BatchSandbox resources, each a dict
        with ``name`` (the sandbox id), ``created_at`` (the resource's
        creationTimestamp, or None) and ``user_id`` (from the claw-data
        volumeMount subPath, or None).

        - Ids with no summary row get one marked ``accessed = FALSE``
          with NULL request fields, a zero request count and
          ``created_at``/``user_id`` set (existing rows are otherwise
          untouched).
        - Existing rows whose ``created_at``/``user_id`` is still NULL
          get it backfilled from the resource.

        Returns ``{"discovered": <n>, "backfilled": <n>}``.
        """
        # One statement for all ids - each round trip to a remote
        # database can be slow.
        deduped = {
            sandbox["name"]: (
                sandbox.get("created_at"),
                sandbox.get("user_id"),
            )
            for sandbox in sandboxes
        }
        if not deduped:
            return {"discovered": 0, "backfilled": 0}
        with self.pool.connection() as conn:
            conn.row_factory = dict_row
            with conn.cursor() as cur:
                cur.execute(
                    _INSERT_DISCOVERED,
                    {
                        "ids": list(deduped),
                        "created": [
                            _ensure_utc(created) if created is not None else None
                            for created, _ in deduped.values()
                        ],
                        "users": [user_id for _, user_id in deduped.values()],
                    },
                )
                flags = [row["inserted"] for row in cur.fetchall()]
        return {
            "discovered": sum(1 for flag in flags if flag),
            "backfilled": sum(1 for flag in flags if not flag),
        }

    def update_node_ips(self, nodes: dict[str, str]) -> int:
        """Refresh ``node_ip`` from the sandbox pods' host IPs.

        ``nodes`` maps sandbox id -> node IP (from the cluster). Rows
        whose id is present get ``node_ip`` set (a rescheduled pod's new
        node overwrites the old value); ids absent from the map are left
        as they are (the pod may be gone or not scheduled yet). Returns
        the number of rows whose value actually changed.
        """
        if not nodes:
            return 0
        # One statement for all ids - each round trip to a remote
        # database can be slow.
        with self.pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE sandbox_access_latest AS latest
                    SET node_ip = mapped.node_ip
                    FROM unnest(%(ids)s::text[], %(ips)s::text[])
                        AS mapped(sandbox_id, node_ip)
                    WHERE latest.sandbox_id = mapped.sandbox_id
                      AND latest.node_ip IS DISTINCT FROM mapped.node_ip
                    """,
                    {"ids": list(nodes), "ips": list(nodes.values())},
                )
                return cur.rowcount

    def sync_deleted_flags(self, live_ids: list[str]) -> dict:
        """Reconcile the ``deleted`` flag against live sandbox resources.

        ``live_ids`` are the names of the BatchSandbox resources currently
        existing in the cluster. Summary rows whose sandbox id is not among
        them are marked deleted (hidden from the UI/API); rows previously
        marked deleted whose id reappears are restored. ``updated_at`` is
        left untouched - it reflects the last request, not the sync.

        Returns ``{"deleted": <n>, "restored": <n>}`` counting rows whose
        flag actually changed.
        """
        with self.pool.connection() as conn:
            with conn.cursor() as cur:
                # An empty live list marks everything deleted; <> ALL ([])
                # is TRUE for every row, so no special case is needed.
                cur.execute(
                    """
                    UPDATE sandbox_access_latest
                    SET deleted = TRUE
                    WHERE NOT deleted AND sandbox_id <> ALL(%(ids)s)
                    """,
                    {"ids": live_ids},
                )
                deleted = cur.rowcount
                cur.execute(
                    """
                    UPDATE sandbox_access_latest
                    SET deleted = FALSE
                    WHERE deleted AND sandbox_id = ANY(%(ids)s)
                    """,
                    {"ids": live_ids},
                )
                restored = cur.rowcount
        return {"deleted": deleted, "restored": restored}


def _normalize(event: dict) -> dict:
    """Coerce an audit event to DB row parameters.

    The ingress sends RFC3339 timestamps with a timezone offset; naive
    timestamps (if any) are assumed to be UTC. Timestamps are truncated
    to whole seconds.
    """
    request_time = event["request_time"]
    if isinstance(request_time, str):
        request_time = datetime.fromisoformat(
            request_time.replace("Z", "+00:00")
        )
    if request_time.tzinfo is None:
        request_time = request_time.replace(tzinfo=timezone.utc)
    request_time = request_time.replace(microsecond=0)

    return {
        "sandbox_id": event["sandbox_id"],
        "uri": event["uri"],
        "method": event["method"],
        "target": event["target"],
        "request_time": request_time,
    }


def _jsonify(row: dict) -> dict:
    """Make a DB row JSON-serializable (datetime -> ISO 8601, seconds only)."""
    return {
        key: value.replace(microsecond=0).isoformat()
        if isinstance(value, datetime)
        else value
        for key, value in row.items()
    }


def _drop_total(row: dict) -> dict:
    """Strip the piggybacked window ``__total`` from a listing row."""
    return {key: value for key, value in row.items() if key != "__total"}


def _ensure_utc(value: datetime) -> datetime:
    """Treat naive filter timestamps as UTC (matches ``_normalize``)."""
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def _like_escape(text: str) -> str:
    """Escape LIKE/ILIKE wildcards so the search input matches literally."""
    return (
        text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    )
