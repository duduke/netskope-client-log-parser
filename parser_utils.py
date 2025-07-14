import re
import pandas as pd
from datetime import datetime, timedelta

# ── NSDEBUGLOG PARSING ──────────────────────────────────────────────────────

def parse_log_lines(lines):
    tunneled_records, bypassed_records = [], []
    pop_entries, rtt_records = [], []
    general_errors, steering_records = [], []
    last_gateway = None
    header_info = {"hostname":"", "os_version":"", "client_version":"", "tenant":""}

    for line in lines:
        # Timestamp
        m_ts = re.match(r'^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)', line)
        if not m_ts:
            continue
        ts_str = m_ts.group(1)
        try:
            timestamp = datetime.strptime(ts_str, "%Y/%m/%d %H:%M:%S.%f")
        except ValueError:
            timestamp = datetime.strptime(ts_str, "%Y/%m/%d %H:%M:%S")

        low = line.lower()

        # Tunneled
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

        # Bypassed
        if "bypassappmgr" in low:
            pm  = re.search(r'process:\s*([^,\n]+)', line, re.IGNORECASE)
            hm  = re.search(r'(?:exception host|host):\s*([^\s,]+)', line, re.IGNORECASE)
            ipm = re.search(r'dest ip:\s*([^\s,]+)', line, re.IGNORECASE)
            if ipm:
                bypassed_records.append((
                    timestamp,
                    pm.group(1).strip() if pm else "UNKNOWN",
                    hm.group(1).strip() if hm else "",
                    ipm.group(1).strip()
                ))

        # PoP connections
        if "tunnel established to gateway" in low or "connecting to gateway-" in low:
            pop_entries.append((timestamp, line.strip()))
            if "connecting to gateway-" in low:
                lg = re.search(r'connecting to (gateway-[^:\s]+)', line, re.IGNORECASE)
                if lg:
                    last_gateway = lg.group(1).strip()

        # RTT
        if "post client rtt" in low and "pop:" in low:
            m_rtt = re.search(r'pop:([^\s]+)\s+ip:([^\s]+)\s+rtt:(\d+)', line)
            if m_rtt:
                rtt_records.append((
                    timestamp,
                    m_rtt.group(1),
                    m_rtt.group(2),
                    int(m_rtt.group(3))
                ))

        # Steering
        if "dynamic steering enhancement" in low:
            steering_records.append(line.strip())

        # General errors/warnings
        if " error " in low or " warn " in low or "err:" in low:
            general_errors.append((timestamp, line.strip()))

        # Header info
        if "config setting sta user agent" in low:
            m_hdr = re.search(r'STA user agent:\s*([^;]+);([^;]+);(.+)', line, re.IGNORECASE)
            if m_hdr:
                header_info["os_version"]     = m_hdr.group(1).strip()
                header_info["client_version"] = m_hdr.group(2).strip()
                header_info["hostname"]       = m_hdr.group(3).strip()

        # Tenant
        if "url:https://addon-" in low:
            m_tnt = re.search(r'url:https://addon-([^\s/]+)', line, re.IGNORECASE)
            if m_tnt:
                header_info["tenant"] = m_tnt.group(1).strip()

    return (
        pd.DataFrame(tunneled_records, columns=["Timestamp","Process","Destination Host","Destination IP"]),
        pd.DataFrame(bypassed_records, columns=["Timestamp","Process","Destination Host","Destination IP"]),
        pop_entries,
        pd.DataFrame(rtt_records,   columns=["Timestamp","PoP","IP","RTT (ms)"]),
        pd.DataFrame(general_errors,columns=["Timestamp","Log Line"]),
        steering_records,
        last_gateway,
        header_info
    )


def filter_by_minutes(df_t, df_b, pops, df_rtt, df_err, steering_records, minutes):
    ts_list = []
    for df in (df_t, df_b, df_err):
        if not df.empty:
            ts_list.append(df["Timestamp"].max())
    if pops:
        ts_list.append(max(ts for ts,_ in pops))
    for ln in steering_records:
        m = re.match(r'^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)', ln)
        if m:
            try:
                t = datetime.strptime(m.group(1), "%Y/%m/%d %H:%M:%S.%f")
            except ValueError:
                t = datetime.strptime(m.group(1), "%Y/%m/%d %H:%M:%S")
            ts_list.append(t)

    if not ts_list:
        return df_t, df_b, [], df_rtt, df_err, []

    cutoff = max(ts_list) - timedelta(minutes=minutes)
    df_t      = df_t[df_t["Timestamp"] >= cutoff]
    df_b      = df_b[df_b["Timestamp"] >= cutoff]
    df_err    = df_err[df_err["Timestamp"]    >= cutoff]
    pops      = [(ts,l) for ts,l in pops if ts >= cutoff]
    steering  = [ln for ln in steering_records if re.match(r'^(\d{4}/\d{2}/\d{2} ', ln)
                 and datetime.strptime(re.match(r'^(\d{4}/\d{2}/\d{2} .*?)', ln).group(1),
                                       "%Y/%m/%d %H:%M:%S.%f") >= cutoff]
    return df_t, df_b, pops, df_rtt, df_err, steering


# ── NPADEBUGLOG PARSING ────────────────────────────────────────────────────

def parse_npa_log_lines(lines):
    tenant_url      = None
    rtt_records     = []
    error_records   = []
    warning_records = []
    tunnel_events   = []
    policy_records  = []

    it = iter(lines)
    for line in it:
        # Timestamp
        m_ts = re.search(r'^\[[^:]+:(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)', line)
        ts = None
        if m_ts:
            try:
                ts = datetime.strptime(m_ts.group(1), "%Y-%m-%d %H:%M:%S.%f")
            except:
                ts = None

        low = line.lower()

        # Tenant URL
        if "set tenant url" in low:
            m_t = re.search(r"Set tenant url\s+(\S+)", line, re.IGNORECASE)
            if m_t:
                tenant_url = m_t.group(1).strip()

        # RTT
        if "ip =" in low and "pop =" in low and "rtt =" in low:
            m_r = re.search(
                r"IP\s*=\s*([^,]+),\s*POP\s*=\s*([^,]+),\s*RTT\s*=\s*(\d+)\s*ms",
                line,
            )
            if m_r:
                rtt_records.append((m_r.group(2), m_r.group(1), int(m_r.group(3))))

        # Errors & Warnings
        if "[error]" in low:
            error_records.append((ts, line.strip()))
        elif "[warn]" in low or "[warning]" in low:
            warning_records.append((ts, line.strip()))

        # Tunnel events
        if "npa client is connecting to" in low or "adding npa tunnel" in low:
            tunnel_events.append(line.strip())

        # Policy Events
        if "adding host rule" in low:
            # hostname
            m_h = re.match(r'^\[([^:]+):', line)
            hostname = m_h.group(1) if m_h else ""
            policy_name = app_name = app_details = publishers = ""

            # next lines
            for _ in range(5):
                try:
                    nxt = next(it).strip()
                except StopIteration:
                    break

                if nxt.lower().startswith("policy name:"):
                    policy_name = nxt.split("Policy Name:",1)[1].strip()
                elif nxt.lower().startswith("app name:"):
                    app_name = nxt.split("App Name:",1)[1].strip()
                elif ";" in nxt:
                    # actual details line (ports/IPs)
                    app_details = nxt
                elif nxt.lower().startswith("publishers:"):
                    publishers = nxt.split("Publishers:",1)[1].strip()
                    break

            policy_records.append({
                "Timestamp":   ts,
                "Hostname":    hostname,
                "Policy Name": policy_name,
                "App Name":    app_name,
                "App Details": app_details,
                "Publishers":  publishers
            })

    df_rtt      = pd.DataFrame(rtt_records,     columns=["PoP","IP","RTT (ms)"])
    df_errors   = pd.DataFrame(error_records,   columns=["Timestamp","Log Line"])
    df_warnings = pd.DataFrame(warning_records, columns=["Timestamp","Log Line"])

    return tenant_url, df_rtt, df_errors, df_warnings, tunnel_events, policy_records
