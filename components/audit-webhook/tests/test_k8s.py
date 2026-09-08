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

"""Tests for the real K8sClient against mocked kubernetes APIs.

These exercise the lazy API-handle caching and response parsing in
``k8s.K8sClient`` - a regression guard for the accessor/attribute name
clash that once made the API accessor return ``None``.
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "utils"))

import k8s


class FakeCustomObjectsApi:
    def list_namespaced_custom_object(self, **kwargs):
        assert kwargs["namespace"] == "ns"
        assert kwargs["group"] == "sandbox.opensandbox.io"
        assert kwargs["plural"] == "batchsandboxes"
        return {
            "items": [
                {"metadata": {"name": "sb-1",
                              "creationTimestamp": "2026-08-30T04:05:06Z"},
                 "spec": {"template": {"spec": {"containers": [{
                     "volumeMounts": [{"name": "claw-data", "mountPath": "/opt/data",
                                       "subPath": "claw/7680071018521559040/v20260729/2.4.6.20260831"}],
                 }]}}}},
                # Offset timestamps are normalized, not converted to UTC.
                {"metadata": {"name": "sb-2",
                              "creationTimestamp": "2026-08-30T12:00:00+08:00"},
                 "spec": {"template": {"spec": {"containers": [{
                     "volumeMounts": [{"name": "claw-data",
                                       "subPath": "claw/1234567890/latest"}],
                 }]}}}},
                # Missing or unparseable timestamps and missing/odd
                # volumeMounts yield None.
                {"metadata": {"name": "sb-3"}},
                {"metadata": {"name": "sb-4", "creationTimestamp": "not-a-time"},
                 "spec": {"template": {"spec": {"containers": [{
                     # claw-data present but not a claw/... subPath.
                     "volumeMounts": [{"name": "claw-data", "subPath": "data"}],
                 }]}}}},
                {"metadata": {"name": "sb-5"},
                 "spec": {"template": {"spec": {"containers": [{
                     "volumeMounts": [{"name": "other", "subPath": "claw/999"}],
                 }]}}}},
            ]
        }


def _fake_pod(sandbox_id, host_ip, owner_kind="BatchSandbox"):
    metadata = SimpleNamespace(labels={}, owner_references=[])
    if sandbox_id:
        metadata.owner_references.append(
            SimpleNamespace(kind=owner_kind, name=sandbox_id)
        )
    return SimpleNamespace(metadata=metadata, status=SimpleNamespace(host_ip=host_ip))


class FakeCoreV1Api:
    def list_namespaced_pod(self, **kwargs):
        assert kwargs["namespace"] == "ns"
        # A pod with a non-BatchSandbox owner, an unscheduled pod (no host
        # IP) and a duplicate pod are ignored.
        return SimpleNamespace(
            items=[
                _fake_pod("sb-1", "10.0.0.1"),
                _fake_pod("sb-other", "10.0.0.9", owner_kind="DaemonSet"),
                _fake_pod("sb-2", None),
                _fake_pod("sb-1", "10.0.0.1"),
            ]
        )


def make_client(monkeypatch):
    monkeypatch.setattr(k8s.config, "load_kube_config", lambda **kwargs: None)
    monkeypatch.setattr(k8s.client, "CustomObjectsApi", FakeCustomObjectsApi)
    monkeypatch.setattr(k8s.client, "CoreV1Api", FakeCoreV1Api)
    return k8s.K8sClient("")


def test_list_batch_sandboxes_parses_creation_timestamps(monkeypatch):
    client = make_client(monkeypatch)

    items = client.list_batch_sandboxes("ns")

    assert [item["name"] for item in items] == ["sb-1", "sb-2", "sb-3", "sb-4", "sb-5"]
    assert items[0]["created_at"] == datetime(
        2026, 8, 30, 4, 5, 6, tzinfo=timezone.utc
    )
    assert items[1]["created_at"] == datetime(
        2026, 8, 30, 12, 0, 0, tzinfo=timezone(timedelta(hours=8))
    )
    assert items[2]["created_at"] is None
    assert items[3]["created_at"] is None
    assert items[4]["created_at"] is None


def test_list_batch_sandboxes_extracts_user_id(monkeypatch):
    """The user id is the 2nd segment of the claw-data volumeMount's subPath."""
    client = make_client(monkeypatch)

    items = client.list_batch_sandboxes("ns")

    assert items[0]["user_id"] == "7680071018521559040"
    assert items[1]["user_id"] == "1234567890"
    # No spec/volumeMounts at all.
    assert items[2]["user_id"] is None
    # claw-data present but subPath does not start with claw/.
    assert items[3]["user_id"] is None
    # A different volume named differently is ignored.
    assert items[4]["user_id"] is None


def test_list_sandbox_pod_nodes_uses_owner_references(monkeypatch):
    client = make_client(monkeypatch)

    nodes = client.list_sandbox_pod_nodes("ns")

    assert nodes == {"sb-1": "10.0.0.1"}


def test_kubeconfig_load_failure_raises_k8s_error(monkeypatch):
    def broken_load(**kwargs):
        raise k8s.config.ConfigException("no kubeconfig")

    monkeypatch.setattr(k8s.config, "load_kube_config", broken_load)
    monkeypatch.setattr(k8s.config, "load_incluster_config", broken_load)
    client = k8s.K8sClient("")

    try:
        client.list_batch_sandboxes("ns")
    except k8s.K8sError as exc:
        assert "kubeconfig" in str(exc)
    else:
        raise AssertionError("expected K8sError")
