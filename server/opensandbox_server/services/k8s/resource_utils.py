# Copyright 2025 Alibaba Group Holding Ltd.
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

"""
Kubernetes resource calculation utilities.
"""

import re
from typing import Any, Dict, Optional

# Threshold separating "normal" (small) from "vip" (large) host pools: 10Gi.
MEMORY_SOFT_AFFINITY_THRESHOLD_BYTES = 10 * 1024 * 1024 * 1024

_MEMORY_UNIT_BYTES = {
    "Ki": 1024,
    "K": 1000,
    "Mi": 1024 ** 2,
    "M": 1000 ** 2,
    "Gi": 1024 ** 3,
    "G": 1000 ** 3,
    "Ti": 1024 ** 4,
    "T": 1000 ** 4,
    "Pi": 1024 ** 5,
    "P": 1000 ** 5,
    "Ei": 1024 ** 6,
    "E": 1000 ** 6,
}


def parse_memory_value_bytes(value: Optional[str]) -> Optional[int]:
    """
    Parse a Kubernetes memory quantity into bytes.

    Supports binary (Ki/Mi/Gi/Ti/Pi/Ei), decimal (K/M/G/T/P/E) and unitless
    byte values, e.g. "512Mi" -> 536870912, "8G" -> 8000000000, "1048576" -> 1048576.

    Returns None when the value is missing or unparseable.
    """
    if value is None:
        return None
    value_str = str(value).strip()

    memory_match = re.match(r'^(\d+(?:\.\d+)?)\s*([KMGTPE]i?)$', value_str)
    if memory_match:
        amount = float(memory_match.group(1))
        unit_bytes = _MEMORY_UNIT_BYTES.get(memory_match.group(2))
        if unit_bytes is None:
            return None
        return int(amount * unit_bytes)

    try:
        amount = float(value_str)
    except ValueError:
        return None
    if amount < 0:
        return None
    return int(amount)


def memory_hosttype_affinity_value(
    value: Optional[str],
    threshold_bytes: int = MEMORY_SOFT_AFFINITY_THRESHOLD_BYTES,
) -> Optional[str]:
    """
    Map a sandbox memory limit to its soft-affinity host type label value.

    Memory limit < 10Gi  -> "normal" (small sandbox, plain hosts)
    Memory limit >= 10Gi -> "vip"   (large sandbox, VIP hosts)

    Returns None when the value is missing or unparseable.
    """
    total_bytes = parse_memory_value_bytes(value)
    if total_bytes is None:
        return None
    return "normal" if total_bytes < threshold_bytes else "vip"


def apply_memory_soft_affinity(
    pod_spec: Dict[str, Any],
    resource_limits: Dict[str, str],
    enabled: bool,
    weight: int = 100,
    threshold_bytes: int = MEMORY_SOFT_AFFINITY_THRESHOLD_BYTES,
) -> None:
    """
    Add a node soft-affinity preference keyed by "hosttype" based on the
    sandbox memory limit:

    - limit <  10Gi -> prefer nodes labeled ``hosttype=normal``
    - limit >= 10Gi -> prefer nodes labeled ``hosttype=vip``

    This is a *preferred* (soft) affinity: scheduling still succeeds when no
    node carries the label. Existing affinity entries are preserved and the
    preference term is appended.
    """
    if not enabled:
        return
    host_type = memory_hosttype_affinity_value(
        resource_limits.get("memory"), threshold_bytes=threshold_bytes
    )
    if not host_type:
        return

    affinity = pod_spec.setdefault("affinity", {})
    if not isinstance(affinity, dict):
        return
    node_affinity = affinity.setdefault("nodeAffinity", {})
    if not isinstance(node_affinity, dict):
        return
    preferred = node_affinity.setdefault(
        "preferredDuringSchedulingIgnoredDuringExecution", []
    )
    if not isinstance(preferred, list):
        return

    preferred.append(
        {
            "weight": weight,
            "preference": {
                "matchExpressions": [
                    {"key": "hosttype", "operator": "In", "values": [host_type]}
                ]
            },
        }
    )


def calculate_resource_requests(limits: Dict[str, str], fraction: float = 0.25) -> Dict[str, str]:
    """
    Calculate resource requests based on limits.
    
    Args:
        limits: Resource limits dict (e.g., {"cpu": "1", "memory": "1Gi"})
        fraction: Fraction of limits to use for requests (default: 0.25 = 1/4)
        
    Returns:
        Resource requests dict with CPU and memory set to fraction of limits.
        Other resources (e.g., gpu) remain unchanged.
    """
    requests = {}
    
    for resource, value in limits.items():
        if resource in ("cpu", "memory"):
            requests[resource] = scale_resource_value(value, fraction)
        else:
            # For other resources (e.g., gpu), keep the same value
            requests[resource] = value
    
    return requests


def scale_resource_value(value: str, factor: float) -> str:
    """
    Scale a resource value by the given factor.
    
    Args:
        value: Resource value string (e.g., "500m", "1Gi", "2")
        factor: Scaling factor (e.g., 0.25 for 1/4)
        
    Returns:
        Scaled resource value string
    """
    # Parse CPU values
    if isinstance(value, (int, float)):
        scaled = float(value) * factor
        # Return integer if whole number, otherwise float with reasonable precision
        if scaled == int(scaled):
            return str(int(scaled))
        return f"{scaled:.3g}"
    
    value_str = str(value)
    
    # Handle CPU millicores (e.g., "500m")
    cpu_match = re.match(r'^(\d+(?:\.\d+)?)m$', value_str)
    if cpu_match:
        millicores = float(cpu_match.group(1))
        scaled_millicores = millicores * factor
        # Return as integer millicores if >= 1, otherwise use cores
        if scaled_millicores >= 1:
            return f"{int(round(scaled_millicores))}m"
        else:
            # Convert to cores (e.g., 0.25)
            cores = scaled_millicores / 1000
            return f"{cores:.3g}"
    
    # Handle CPU cores without unit (e.g., "1", "0.5")
    cpu_cores_match = re.match(r'^(\d+(?:\.\d+)?)$', value_str)
    if cpu_cores_match:
        cores = float(cpu_cores_match.group(1))
        scaled_cores = cores * factor
        if scaled_cores == int(scaled_cores):
            return str(int(scaled_cores))
        return f"{scaled_cores:.3g}"
    
    # Handle memory with units (e.g., "512Mi", "1Gi", "1024Ki")
    memory_match = re.match(r'^(\d+(?:\.\d+)?)(Ki|Mi|Gi|Ti|Pi|Ei)$', value_str)
    if memory_match:
        amount = float(memory_match.group(1))
        unit = memory_match.group(2)
        scaled_amount = amount * factor
        
        # Try to keep the same unit if result is >= 1
        if scaled_amount >= 1:
            if scaled_amount == int(scaled_amount):
                return f"{int(scaled_amount)}{unit}"
            return f"{scaled_amount:.0f}{unit}"
        else:
            # Convert to smaller unit
            unit_map = {"Ki": 1024, "Mi": 1024, "Gi": 1024, "Ti": 1024, "Pi": 1024, "Ei": 1024}
            units = ["Ki", "Mi", "Gi", "Ti", "Pi", "Ei"]
            current_idx = units.index(unit)
            
            # Convert to next smaller unit
            if current_idx > 0:
                smaller_unit = units[current_idx - 1]
                converted_amount = scaled_amount * unit_map[unit]
                if converted_amount == int(converted_amount):
                    return f"{int(converted_amount)}{smaller_unit}"
                return f"{converted_amount:.0f}{smaller_unit}"
            else:
                # Already at smallest unit (Ki), return as is
                return f"{scaled_amount:.0f}{unit}"
    
    # Handle plain numbers (no unit)
    try:
        num_value = float(value_str)
        scaled_value = num_value * factor
        if scaled_value == int(scaled_value):
            return str(int(scaled_value))
        return f"{scaled_value:.3g}"
    except ValueError:
        # If parsing fails, return original value
        return value_str
