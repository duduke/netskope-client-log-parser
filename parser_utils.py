import re
import pandas as pd
from datetime import datetime, timedelta

def parse_log_lines(lines):
    tunneled_records = []
    bypassed_records = []
    pop_entries = []
    rtt_records = []
    general_errors = []
    steering_records = []
    last_gateway = None
    header_info = {"hostname": "", "os_version": "", "client_version": "", "tenant": ""}

    for line in lines:
        # 1) Extract timestamp
        m_ts = re.match(r'^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)', line)
        if not m_ts:
            continue
        ts_str = m_ts.group(1)
        try:
            timestamp = datetime.strptime(ts_str, "%Y/%m/%d %H:%M:%S.%f")
        except ValueError:
            timestamp = datetime.strptime(ts_str, "%Y/%m/%d %H:%M:%S")

        low = line.lower()

        # 2) Tunneled traffic
        if "tunneling flow" in low:
            pm  = re.search(r'process:\s*(.*?)(?:,| to host:)', line)
            hm  = re.search(r'host:\s*([^\s,]+)', line)
            ipm = re.search(r'addr:\s*([^\s,]+)', line)
            if pm and hm and ipm:
                tunneled_records.append((
                    timestamp,
                    pm.group(1).strip(),
                    hm.group(1).strip(),
                    ipm.group(1).strip()
                ))

        # 3) Bypassed traffic
        if "bypassappmgr" in low:
            pm  = re.search(r'process:\s*([^,\n]+)', line, re.IGNORECASE)
            hm  = re.search(r'(?:exception host|host):\s*([^\s,]+)', line, re.IGNORECASE)
            ipm = re.search(r'dest ip:\s*([^\s,]+)', line, re.IGNORECASE)
            if ipm:
                proc = pm.group(1).strip() if pm else "UNKNOWN"
                host = hm.group(1).strip() if hm else ""
                bypassed_records.append((
                    timestamp,
                    proc,
                    host,
                    ipm.group(1).strip()
                ))

        # 4) PoP connections
        if "tunnel established to gateway" in low or "connecting to gateway-" in low:
            pop_entries.append((timestamp, line.strip()))
            if "connecting to gateway-" in low:
                lg = re.search(r'connecting to (gateway-[^:\s]+)', line, re.IGNORECASE)
                if lg:
                    last_gateway = lg.group(1).strip()

        # 5) RTT measurements
        if "post client rtt" in low and "pop:" in low:
            m_rtt = re.search(r'pop:([^\s]+)\s+ip:([^\s]+)\s+rtt:(\d+)', line)
            if m_rtt:
                rtt_records.append((
                    timestamp,
                    m_rtt.group(1),
                    m_rtt.group(2),
                    int(m_rtt.group(3))
                ))

        # 6) Traffic steering messages
        if "dynamic steering enhancement" in low:
            steering_records.append(line.strip())

        # 7) General Errors & Warnings
        if " error " in low or " warn " in low or "err:" in low:
            general_errors.append((timestamp, line.strip()))

        # 8) Client header info
        if "config setting sta user agent" in low:
            m_hdr = re.search(r'STA user agent:\s*([^;]+);([^;]+);(.+)', line, re.IGNORECASE)
            if m_hdr:
                header_info["os_version"]     = m_hdr.group(1).strip()
                header_info["client_version"] = m_hdr.group(2).strip()
                header_info["hostname"]       = m_hdr.group(3).strip()

        # 9) Tenant extraction
        if "url:https://addon-" in low:
            m_tnt = re.search(r'url:https://addon-([^\s/]+)', line, re.IGNORECASE)
            if m_tnt:
                header_info["tenant"] = m_tnt.group(1).strip()

    return (
        pd.DataFrame(tunneled_records, columns=["Timestamp", "Process", "Destination Host", "Destination IP"]),
        pd.DataFrame(bypassed_records, columns=["Timestamp", "Process", "Destination Host", "Destination IP"]),
        pop_entries,
        pd.DataFrame(rtt_records,    columns=["Timestamp", "PoP", "IP", "RTT (ms)"]),
        pd.DataFrame(general_errors, columns=["Timestamp", "Log Line"]),
        steering_records,
        last_gateway,
        header_info
    )


def filter_by_minutes(df_tunnel, df_bypass, pop_entries, df_rtt, df_errors, steering_records, minutes):
    # Collect the newest timestamp from each source
    ts_list = []
    for df in (df_tunnel, df_bypass, df_errors):
        if not df.empty:
            ts_list.append(df["Timestamp"].max())
    if pop_entries:
        ts_list.append(max(ts for ts, _ in pop_entries))

    # Include steering_records timestamps
    for ln in steering_records:
        m = re.match(r'^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)', ln)
        if not m:
            continue
        ts_str = m.group(1)
        try:
            t = datetime.strptime(ts_str, "%Y/%m/%d %H:%M:%S.%f")
        except ValueError:
            t = datetime.strptime(ts_str, "%Y/%m/%d %H:%M:%S")
        ts_list.append(t)

    # If nothing found, return early
    if not ts_list:
        return df_tunnel, df_bypass, [], df_rtt, df_errors, []

    latest = max(ts_list)
    cutoff = latest - timedelta(minutes=minutes)

    # Filter each
    df_tunnel     = df_tunnel[df_tunnel["Timestamp"] >= cutoff]
    df_bypass     = df_bypass[df_bypass["Timestamp"] >= cutoff]
    df_errors     = df_errors[df_errors["Timestamp"] >= cutoff]
    pop_entries   = [(ts, l) for ts, l in pop_entries if ts >= cutoff]
    # RTT has its own timestamp column so you can filter similarly if desired
    df_rtt_filtered = df_rtt[df_rtt["Timestamp"] >= cutoff] if "Timestamp" in df_rtt.columns else df_rtt

    # Filter steering messages
    filtered_steering = []
    for ln in steering_records:
        m = re.match(r'^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)', ln)
        if not m:
            continue
        ts_str = m.group(1)
        try:
            t = datetime.strptime(ts_str, "%Y/%m/%d %H:%M:%S.%f")
        except ValueError:
            t = datetime.strptime(ts_str, "%Y/%m/%d %H:%M:%S")
        if t >= cutoff:
            filtered_steering.append(ln)

    return df_tunnel, df_bypass, pop_entries, df_rtt_filtered, df_errors, filtered_steering
