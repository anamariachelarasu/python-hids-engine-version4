from typing import Any, Dict, List, Optional, Set
from sigma.rule import SigmaDetection, SigmaRule

#mapping between sigma categories and windows (channel, event_ids)
CATEGORY_MAPPING: Dict[str, Dict[str, Any]] = {
    "process_creation": {
        "channels": ["Microsoft-Windows-Sysmon/Operational", "Security"],
        "event_ids": [1, 4688],
    },
    "network_connection": {
        "channels": ["Microsoft-Windows-Sysmon/Operational"],
        "event_ids": [3],
    },
    "sysmon_status": {
        "channels": ["Microsoft-Windows-Sysmon/Operational"],
        "event_ids": [4, 16],
    },
    "driver_load": {
        "channels": ["Microsoft-Windows-Sysmon/Operational"],
        "event_ids": [6],
    },
    "image_load": {
        "channels": ["Microsoft-Windows-Sysmon/Operational"],
        "event_ids": [7],
    },
    "create_remote_thread": {
        "channels": ["Microsoft-Windows-Sysmon/Operational"],
        "event_ids": [8],
    },
    "raw_access_thread": {
        "channels": ["Microsoft-Windows-Sysmon/Operational"],
        "event_ids": [9],
    },
    "process_access": {
        "channels": ["Microsoft-Windows-Sysmon/Operational"],
        "event_ids": [10],
    },
    "file_event": {
        "channels": ["Microsoft-Windows-Sysmon/Operational"],
        "event_ids": [11],
    },
    "file_change": {
        "channels": ["Microsoft-Windows-Sysmon/Operational"],
        "event_ids": [2],
    },
    "file_rename": {
        "channels": ["Microsoft-Windows-Sysmon/Operational"],
        "event_ids": [11],
    },
    "file_delete": {
        "channels": ["Microsoft-Windows-Sysmon/Operational"],
        "event_ids": [23],
    },
    "file_executable_detected": {
        "channels": ["Microsoft-Windows-Sysmon/Operational"],
        "event_ids": [29],
    },
    "file_delete_detected": {
        "channels": ["Microsoft-Windows-Sysmon/Operational"],
        "event_ids": [26],
    },
    "file_block_executable": {
        "channels": ["Microsoft-Windows-Sysmon/Operational"],
        "event_ids": [27],
    },
    "file_block_executable": {
        "channels": ["Microsoft-Windows-Sysmon/Operational"],
        "event_ids": [27],
    },
    "file_block_executable": {
        "channels": ["Microsoft-Windows-Sysmon/Operational"],
        "event_ids": [28],
    },
    "registry_event": {
        "channels": ["Microsoft-Windows-Sysmon/Operational"],
        "event_ids": [12, 13, 14],
    },
    "registry_add": {
        "channels": ["Microsoft-Windows-Sysmon/Operational"],
        "event_ids": [12, 14],
    },
    "registry_delete": {
        "channels": ["Microsoft-Windows-Sysmon/Operational"],
        "event_ids": [12],
    },
    "registry_set": {
        "channels": ["Microsoft-Windows-Sysmon/Operational"],
        "event_ids": [13],
    },
    "pipe_created": {
        "channels": ["Microsoft-Windows-Sysmon/Operational"],
        "event_ids": [17, 18],
    },
    "wmi_event": {
        "channels": ["Microsoft-Windows-Sysmon/Operational"],
        "event_ids": [19, 20, 21],
    },
    "dns_query": {
        "channels": ["Microsoft-Windows-Sysmon/Operational"],
        "event_ids": [22],
    },
    "clipboard_capture": {
        "channels": ["Microsoft-Windows-Sysmon/Operational"],
        "event_ids": [24],
    },
    "process_tampering": {
        "channels": ["Microsoft-Windows-Sysmon/Operational"],
        "event_ids": [25],
    },
    "create_stream_hash": {
        "channels": ["Microsoft-Windows-Sysmon/Operational"],
        "event_ids": [15],
    },
    "ps_script": {
        "channels": ["Microsoft-Windows-PowerShell/Operational"],
        "event_ids": [4104],
    },
    "ps_module": {
        "channels": ["Microsoft-Windows-PowerShell/Operational"],
        "event_ids": [4103],
    },
    "ps_classic_start": {
        "channels": ["Windows PowerShell"],
        "event_ids": [400],
    },
    "ps_classic_provider_start": {
        "channels": ["Windows PowerShell"],
        "event_ids": [600],
    },
    "sysmon_error": {
        "channels": ["Microsoft-Windows-Sysmon/Operational"],
        "event_ids": [255],
    },
}

# mapping for sigma service definitions to windows channels
SERVICE_MAPPING: Dict[str, Dict[str, Any]] = {
    "security": {"channels": ["Security"]},
    "system": {"channels": ["System"]},
    "application": {"channels": ["Application"]},
    "powershell": {"channels": ["Microsoft-Windows-PowerShell/Operational"]},
    "powershell-classic": {"channels": ["Windows PowerShell"]},
    "sysmon": {"channels": ["Microsoft-Windows-Sysmon/Operational"]},
    "directory_service": {"channels": ["Directory Service"]},
    "dns-server": {"channels": ["DNS Server"]},
    "dhcp": {"channels": ["Microsoft-Windows-DHCP-Server/Operational"]},
    "firewall": {"channels": ["Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"]},
    "msexchange-management": {"channels": ["MSExchange Management"]},
    "applocker": { "channels": ["Microsoft-Windows-AppLocker/EXE and DLL",
            "Microsoft-Windows-AppLocker/MSI and Script",]
    },
    "codeintegrity-operational": {"channels": ["Microsoft-Windows-CodeIntegrity/Operational"]},
    "taskscheduler": {"channels": ["Microsoft-Windows-TaskScheduler/Operational"]},
    "windefend": {"channels": ["Microsoft-Windows-Windows Defender/Operational"]},
    "ntds": {"channels": ["Directory Service"]},
}

def extract_target_metadata(rule: SigmaRule) -> Dict[str, Any]:
    #extract target channels, event ids and classification source from any sigma rule
    #using set() to avoid duplicates
    detection_eids: Set[int] = set()
    detection_channels: Set[str] = set()

    def walk_detection(det: Any) -> None:
        #recursively traverse detection tree to collect explicit event ids and channels
        for item in getattr(det, "detection_items", []):
            if isinstance(item, SigmaDetection):
                walk_detection(item)
            elif hasattr(item, "field") and item.field is not None:
                field_lower = str(item.field).lower()
                if isinstance(item.value, list):
                    vals = item.value
                else:
                    vals = [item.value]

                if field_lower in ("eventid", "event_id", "winlog.event_id"):
                    for v in vals:
                        try:
                            detection_eids.add(int(str(v).strip()))
                        except (ValueError, TypeError):
                            pass
                elif field_lower in ("channel", "winlog.channel"):
                    for v in vals:
                        if v is not None:
                            detection_channels.add(str(v).strip())

    #inspect positive detection selections, skipping filters and exclusions
    if hasattr(rule, "detection") and hasattr(rule.detection, "detections"):
        for name, det in rule.detection.detections.items():
            if name.lower().startswith(("filter", "exclu")):
                continue
            walk_detection(det)

    raw_svc = getattr(rule.logsource, "service", None)
    raw_cat = getattr(rule.logsource, "category", None)

    if raw_svc:
        svc = str(raw_svc).lower().strip()
    else:
        svc = None

    if raw_cat:
        cat = str(raw_cat).lower().strip()
    else:
        cat = None

    #combine explicit detection channels with channels inferred from category and service
    inferred_channels: Set[str] = set(detection_channels)
    if cat and cat in CATEGORY_MAPPING:
        inferred_channels.update(CATEGORY_MAPPING[cat]["channels"])
    if svc and svc in SERVICE_MAPPING:
        inferred_channels.update(SERVICE_MAPPING[svc]["channels"])

    #priority 1: eventid explicitly defined in positive detection selections
    if detection_eids:
        return {
            "logsource_category": cat,
            "logsource_service": svc,
            "target_channels": sorted(inferred_channels),
            "target_event_ids": sorted(detection_eids),
            "target_source": "detection",
        }

    #priority 2: mapped logsource category
    if cat and cat in CATEGORY_MAPPING:
        cat_entry = CATEGORY_MAPPING[cat]
        channels = sorted(inferred_channels or set(cat_entry["channels"]))
        return {
            "logsource_category": cat,
            "logsource_service": svc,
            "target_channels": channels,
            "target_event_ids": sorted(cat_entry["event_ids"]),
            "target_source": "logsource",
        }

    #priority 3: mapped logsource service (any EventID in those channels)
    if svc and svc in SERVICE_MAPPING:
        svc_entry = SERVICE_MAPPING[svc]
        channels = sorted(inferred_channels or set(svc_entry["channels"]))
        return {
            "logsource_category": cat,
            "logsource_service": svc,
            "target_channels": channels,
            "target_event_ids": [],
            "target_source": "service",
        }

    #generic logsource
    return {
        "logsource_category": cat,
        "logsource_service": svc,
        "target_channels": sorted(inferred_channels),
        "target_event_ids": [],
        "target_source": "unknown",
    }