
import re
import pandas as pd
from datetime import datetime, timedelta

def parse_log_lines(lines):
    tunneled_records = []
    bypassed_records = []
    pop_entries = []
    rtt_records = []
    general_errors = []
    last_gateway = None
    steering_modes = []
    hostname_info = {"hostname": "", "os_version": "", "client_version": "", "tenant": ""}

    for line in lines:
        timestamp_match = re.match(r'^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)', line)
        timestamp = None
        if timestamp_match:
            try:
                timestamp = datetime.strptime(timestamp_match.group(1), "%Y/%m/%d %H:%M:%S.%f")
            except ValueError:
                try:
                    timestamp = datetime.strptime(timestamp_match.group(1), "%Y/%m/%d %H:%M:%S")
                except ValueError:
                    continue

        # Tunneled traffic
        if "tunneling flow" in line.lower():
            process_match = re.search(r'process:\s*(.*?)(?:,| to host:)', line)
            host_match = re.search(r'host:\s*([^\s,]+)', line)
            ip_match = re.search(r'host:\s*[^\s,]+,\s*addr:\s*([^\s,]+)', line)
            if timestamp and process_match and host_match and ip_match:
                tunneled_records.append((timestamp, process_match.group(1).strip(), host_match.group(1), ip_match.group(1)))

        # Bypassed traffic
        elif "bypassappmgr" in line.lower():
            host_match = re.search(r'exception host:\s*([^\s,]+)', line, re.IGNORECASE)
            process_match = re.search(r'process:\s*([^,\n]+)', line, re.IGNORECASE)
            ip_match = re.search(r'Dest IP:\s*([^\s,]+)', line, re.IGNORECASE)
            if timestamp and host_match and ip_match:
                process = process_match.group(1).strip() if process_match else "UNKNOWN"
                bypassed_records.append((timestamp, process, host_match.group(1), ip_match.group(1)))

        # PoP established
        if "tunnel established to gateway" in line.lower() and "pop:" in line.lower():
            if timestamp:
                pop_entries.append((timestamp, line.strip()))

        # RTT pop latency
        if "post client rtt" in line.lower() and "pop:" in line.lower():
            rtt_match = re.search(r'pop:([^\s]+)\s+ip:([^\s]+)\s+rtt:(\d+)', line)
            if timestamp and rtt_match:
                rtt_records.append((timestamp, rtt_match.group(1), rtt_match.group(2), int(rtt_match.group(3))))

        # General warnings and errors
        if timestamp and (' error ' in line.lower() or ' warn ' in line.lower()):
            general_errors.append((timestamp, line.strip()))

        # Last connected PoP via gateway connection
        if "connecting to gateway-" in line.lower():
            match = re.search(r'connecting to (gateway-[^:]+)', line, re.IGNORECASE)
            if match:
                last_gateway = match.group(1)

        # Traffic steering mode
        if "dynamic steering enhancement" in line.lower():
            steering_modes.append(line.strip())

        # Tenant name
        if "config host:addon.goskope.com url:" in line.lower():
            url_match = re.search(r'url:https://addon-([^.]+\..+)', line)
            if url_match:
                hostname_info["tenant"] = url_match.group(1).strip()

        # OS/client version/hostname
        if "config setting sta user agent" in line.lower():
            agent_match = re.search(r'STA user agent:\s*(.*?);(.*?);(.*)$', line)
            if agent_match:
                hostname_info["os_version"] = agent_match.group(1).strip()
                hostname_info["client_version"] = agent_match.group(2).strip()
                hostname_info["hostname"] = agent_match.group(3).strip()

    return (
        pd.DataFrame(tunneled_records, columns=["Timestamp", "Process", "Destination Host", "Destination IP:Port"]),
        pd.DataFrame(bypassed_records, columns=["Timestamp", "Process", "Destination Host", "Destination IP"]),
        pop_entries,
        pd.DataFrame(rtt_records, columns=["Timestamp", "PoP", "IP", "RTT (ms)"]),
        pd.DataFrame(general_errors, columns=["Timestamp", "Log Line"]),
        last_gateway,
        steering_modes,
        hostname_info
    )

def filter_by_minutes(df_tunnel, df_bypass, pop_entries, df_rtt, df_generalerr, minutes):
    timestamp_sources = []

    for df in [df_tunnel, df_bypass, df_rtt, df_generalerr]:
        if not df.empty:
            timestamp_sources.append(df["Timestamp"])
    if pop_entries:
        timestamp_sources.append(pd.Series([ts for ts, _ in pop_entries]))

    if not timestamp_sources:
        return df_tunnel, df_bypass, [], df_rtt, df_generalerr

    all_timestamps = pd.concat(timestamp_sources)
    latest = all_timestamps.max()
    cutoff = latest - timedelta(minutes=minutes)

    df_tunnel = df_tunnel[df_tunnel["Timestamp"] >= cutoff]
    df_bypass = df_bypass[df_bypass["Timestamp"] >= cutoff]
    df_rtt = df_rtt[df_rtt["Timestamp"] >= cutoff]
    df_generalerr = df_generalerr[df_generalerr["Timestamp"] >= cutoff]
    pop_entries = [(ts, line) for ts, line in pop_entries if ts >= cutoff]

    return df_tunnel, df_bypass, pop_entries, df_rtt, df_generalerr
