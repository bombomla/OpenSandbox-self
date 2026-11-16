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

"""Tests for the TOML config loader."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "utils"))

from config import _DEFAULTS, load_config, resolve_config_path


def write_config(tmp_path, content):
    path = tmp_path / "audit.toml"
    path.write_text(content, encoding="utf-8")
    return path


def test_missing_file_uses_defaults(tmp_path):
    config = load_config(tmp_path / "nonexistent.toml")

    assert config == _DEFAULTS


def test_config_overrides_defaults(tmp_path):
    path = write_config(
        tmp_path,
        """
[server]
host = "127.0.0.1"
port = 9000
ui_password = "secret"

[database]
url = "postgresql://audit@db:5432/audit"
pool_min = 2
pool_max = 20

[kubernetes]
kubeconfig = "/etc/audit/kubeconfig"
namespace = "opensandbox"
sync_interval = 300

[log]
level = "debug"
""",
    )

    config = load_config(path)

    assert config["host"] == "127.0.0.1"
    assert config["port"] == 9000
    assert config["ui_password"] == "secret"
    assert config["database_url"] == "postgresql://audit@db:5432/audit"
    assert config["db_pool_min"] == 2
    assert config["db_pool_max"] == 20
    assert config["kubeconfig"] == "/etc/audit/kubeconfig"
    assert config["k8s_namespace"] == "opensandbox"
    assert config["k8s_sync_interval"] == 300
    assert config["log_level"] == "debug"


def test_partial_config_keeps_other_defaults(tmp_path):
    path = write_config(tmp_path, '[database]\nurl = "postgresql://x"\n')

    config = load_config(path)

    assert config["database_url"] == "postgresql://x"
    assert config["host"] == _DEFAULTS["host"]
    assert config["ui_password"] == _DEFAULTS["ui_password"]


def test_default_excluded_uri_suffixes(tmp_path):
    config = load_config(tmp_path / "nonexistent.toml")

    assert config["excluded_uri_suffixes"] == ["ping"]


def test_excluded_uri_suffixes_multiple_entries(tmp_path):
    path = write_config(
        tmp_path,
        '[events]\nexcluded_uri_suffixes = ["ping", "healthz", "/status"]\n',
    )

    config = load_config(path)

    assert config["excluded_uri_suffixes"] == ["ping", "healthz", "/status"]


def test_excluded_uri_suffixes_single_string(tmp_path):
    path = write_config(tmp_path, '[events]\nexcluded_uri_suffixes = "ping"\n')

    config = load_config(path)

    assert config["excluded_uri_suffixes"] == ["ping"]


def test_excluded_uri_suffixes_invalid_type_raises(tmp_path):
    path = write_config(tmp_path, "[events]\nexcluded_uri_suffixes = [1, 2]\n")

    with pytest.raises(ValueError, match="excluded_uri_suffixes"):
        load_config(path)


def test_default_whitelist_users(tmp_path):
    config = load_config(tmp_path / "nonexistent.toml")

    assert config["whitelist_users"] == []


def test_whitelist_users_multiple_entries(tmp_path):
    path = write_config(
        tmp_path,
        '[whitelist]\nusers = ["u-1", "u-2", "u-3"]\n',
    )

    config = load_config(path)

    assert config["whitelist_users"] == ["u-1", "u-2", "u-3"]


def test_whitelist_users_single_string(tmp_path):
    path = write_config(tmp_path, '[whitelist]\nusers = "u-1"\n')

    config = load_config(path)

    assert config["whitelist_users"] == ["u-1"]


def test_whitelist_users_trims_and_drops_blank_entries(tmp_path):
    path = write_config(
        tmp_path,
        '[whitelist]\nusers = [" u-1 ", "", "  "]\n',
    )

    config = load_config(path)

    assert config["whitelist_users"] == ["u-1"]


def test_whitelist_users_invalid_type_raises(tmp_path):
    path = write_config(tmp_path, "[whitelist]\nusers = [1, 2]\n")

    with pytest.raises(ValueError, match="whitelist"):
        load_config(path)


def test_default_memory_alert_names_and_stale_days(tmp_path):
    config = load_config(tmp_path / "nonexistent.toml")

    assert config["memory_alert_names"] == []
    assert config["stale_days"] == 7


def test_memory_alert_names_multiple_entries(tmp_path):
    path = write_config(
        tmp_path,
        '[alerts]\nmemory_alert_names = ["HighMemory", "HostMemoryUsage"]\n',
    )

    config = load_config(path)

    assert config["memory_alert_names"] == ["HighMemory", "HostMemoryUsage"]


def test_memory_alert_names_single_string(tmp_path):
    path = write_config(tmp_path, '[alerts]\nmemory_alert_names = "HighMemory"\n')

    config = load_config(path)

    assert config["memory_alert_names"] == ["HighMemory"]


def test_memory_alert_names_invalid_type_raises(tmp_path):
    path = write_config(tmp_path, "[alerts]\nmemory_alert_names = 42\n")

    with pytest.raises(ValueError, match="memory_alert_names"):
        load_config(path)


def test_stale_days_override(tmp_path):
    path = write_config(tmp_path, "[alerts]\nstale_days = 14\n")

    config = load_config(path)

    assert config["stale_days"] == 14


def test_default_stop_settings(tmp_path):
    config = load_config(tmp_path / "nonexistent.toml")

    assert config["stop_sandboxes"] is False
    assert config["stop_url"] == "http://10.68.205.224:8000/claw-catalog/stop"
    assert config["stop_slug"] == "v20260427"


def test_stop_settings_override(tmp_path):
    path = write_config(
        tmp_path,
        '[alerts]\nstop_sandboxes = true\nstop_url = "http://stop:8000/claw-catalog/stop"\nstop_slug = "v19700101"\n',
    )

    config = load_config(path)

    assert config["stop_sandboxes"] is True
    assert config["stop_url"] == "http://stop:8000/claw-catalog/stop"
    assert config["stop_slug"] == "v19700101"


def test_stop_sandboxes_must_be_boolean(tmp_path):
    path = write_config(tmp_path, '[alerts]\nstop_sandboxes = "yes"\n')

    with pytest.raises(ValueError, match="stop_sandboxes"):
        load_config(path)


def test_stop_url_must_be_a_string(tmp_path):
    path = write_config(tmp_path, "[alerts]\nstop_url = 42\n")

    with pytest.raises(ValueError, match="stop_url"):
        load_config(path)


def test_unknown_keys_and_sections_ignored(tmp_path):
    path = write_config(
        tmp_path,
        '[server]\nhost = "0.0.0.0"\nfuture_key = 1\n\n[future_section]\nx = 2\n',
    )

    config = load_config(path)

    assert config["host"] == "0.0.0.0"


def test_malformed_toml_raises(tmp_path):
    path = write_config(tmp_path, "not [ valid toml")

    with pytest.raises(Exception):
        load_config(path)


def test_non_integer_port_raises(tmp_path):
    path = write_config(tmp_path, '[server]\nport = "eighty"\n')

    with pytest.raises(ValueError, match="port"):
        load_config(path)


def test_resolve_config_path_env_override(monkeypatch, tmp_path):
    monkeypatch.setenv("AUDIT_CONFIG_PATH", str(tmp_path / "custom.toml"))

    assert resolve_config_path() == tmp_path / "custom.toml"

    monkeypatch.delenv("AUDIT_CONFIG_PATH")
    assert resolve_config_path().name == "audit.toml"
