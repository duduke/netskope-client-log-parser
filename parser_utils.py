import re
from datetime import datetime, timedelta
import pandas as pd

# ─────────────────────────────────────────────────────────────────────────────
# NSDEBUGLOG PARSING
# ─────────────────────────────────────────────────────────────────────────────

def parse_log_lines(lines):
    """
    Parse an nsdebuglog file into:
      df_tunnel, df_bypass, pop_entries, df_rtt, df_errors,
      steering_records, last_gateway, header_info
    """
    tunnel_records   = []
    bypass_records   = []
    pop_entries      = []
    rtt_records      = []
    error_records    = []
    steering_records = []
    last_gateway     = None
    header_info      = {
        "hostname": None,
        "os_version": None,
        "client_version": None,
        "tenant": None,
    }

    # Precompile patterns
    re_ts        = re.compile(r'^(?P<ts>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}\.\d+)')
    re_steer     = re.compile(r'dynamic steering enhancement:', re.IGNORECASE)
    re_pop       = re.compile(r'gateway:\s*([^,]+), pop:\s*([^,]+)', re.IGNORECASE)
    re_rtt       = re.compile(
        r'post client rtt pop:([^ ]+)\s+ip:([^ ]+)\s+rtt:(\d+)', re.IGNORECASE
    )
    re_error     = re.compile(r'(?:err|error|warn|warning):', re.IGNORECASE)

    # Two bypass patterns:
    re_bypass1   = re.compile(
        r'bypassing flow to (?:exception host|host):\s*([^,]+),\s*'
        r'process:\s*([^,]+),\s*Dest IP:\s*([^,]+)',
        re.IGNORECASE
    )
    re_bypass2   = re.compile(
        r'Bypassing connection from process:\s*([^,]+),\s*'
        r'host:\s*([^,]+),', 
        re.IGNORECASE
    )

    re_tunnel    = re.compile(
        r'Tunneling flow from addr:[^,]+,\s*'
        r'process:\s*(.*?)\s+to host:\s*([^,]+),\s*addr:\s*([^:,\s]+)',
        re.IGNORECASE
    )
    re_header    = re.compile(
        r'Config setting STA user agent:\s*(?P<os>.+?);\s*'
        r'Netskope ST Agent\s*(?P<cv>[^;]+);(?P<host>.+)',
        re.IGNORECASE
    )
    re_tenant    = re.compile(r'url:https://addon-(?P<tenant>[^ ]+)', re.IGNORECASE)
    re_connect   = re.compile(
        r'nsTunnel DTLS Connecting to gateway-(?P<gw>[^:]+)\.goskope\.com',
        re.IGNORECASE
    )

    for raw in lines:
        ln = raw.rstrip()
        m_ts = re_ts.match(ln)
        if not m_ts:
            continue
        ts = datetime.strptime(m_ts.group("ts"), "%Y/%m/%d %H:%M:%S.%f")

        # 1) Bypass pattern #1: flow to exception host + Dest IP
        m1 = re_bypass1.search(ln)
        if m1:
            bypass_records.append({
                "Timestamp": ts,
                "Process": m1.group(2).strip(),
                "Destination Host": m1.group(1).strip(),
                "Destination IP": m1.group(3).strip(),
                "Raw": ln
            })
            continue

        # 2) Bypass pattern #2: connection from process + host only
        m2 = re_bypass2.search(ln)
        if m2:
            bypass_records.append({
                "Timestamp": ts,
                "Process": m2.group(1).strip(),
                "Destination Host": m2.group(2).strip(),
                "Destination IP": "",    # no IP field in this pattern
                "Raw": ln
            })
            continue

        # Tunnel flows
        m_t = re_tunnel.search(ln)
        if m_t:
            tunnel_records.append({
                "Timestamp": ts,
                "Process": m_t.group(1).strip(),
                "Destination Host": m_t.group(2).strip(),
                "Destination IP": m_t.group(3).strip(),
                "Raw": ln
            })
            continue

        # PoP entries
        m_p = re_pop.search(ln)
        if m_p:
            pop_entries.append((ts, ln))
            continue

        # RTT events (NS)
        m_r = re_rtt.search(ln)
        if m_r:
            rtt_records.append({
                "Timestamp": ts,
                "Pop": m_r.group(1),
                "IP": m_r.group(2),
                "RTT": int(m_r.group(3)),
                "Raw": ln
            })
            continue

        # Steering messages
        if re_steer.search(ln):
            steering_records.append(ln)
            continue

        # Errors & Warnings
        if re_error.search(ln):
            error_records.append({
                "Timestamp": ts,
                "Message": ln
            })
            continue

        # Header (OS / client / hostname)
        m_h = re_header.search(ln)
        if m_h and not header_info["hostname"]:
            header_info["os_version"]     = m_h.group("os").strip()
            header_info["client_version"] = m_h.group("cv").strip()
            header_info["hostname"]       = m_h.group("host").strip()
            continue

        # Tenant
        m_tn = re_tenant.search(ln)
        if m_tn and not header_info["tenant"]:
            header_info["tenant"] = m_tn.group("tenant").strip()
            continue

        # Last gateway connect
        m_c = re_connect.search(ln)
        if m_c:
            last_gateway = m_c.group("gw").strip()
            continue

    # Build DataFrames
    df_tunnel = pd.DataFrame(tunnel_records)
    df_bypass = pd.DataFrame(bypass_records)
    df_rtt    = pd.DataFrame(rtt_records)
    df_errs   = pd.DataFrame(error_records)

    return (
        df_tunnel,
        df_bypass,
        pop_entries,
        df_rtt,
        df_errs,
        steering_records,
        last_gateway,
        header_info,
    )


def filter_ns_by_minutes(df_tun, df_byp, pops, df_rtt, df_errs, steer, minutes):
    """
    Filter nsdebuglog entries to only those from the last `minutes` minutes
    (relative to the latest timestamp in the log).
    """
    # Gather latest timestamp across all records
    all_ts = []
    for df in (df_tun, df_byp, df_rtt, df_errs):
        if "Timestamp" in df.columns and not df.empty:
            all_ts.append(df["Timestamp"].max())
    if pops:
        all_ts.append(max(ts for ts,_ in pops))
    for ln in steer:
        try:
            all_ts.append(datetime.strptime(ln[:23], "%Y/%m/%d %H:%M:%S.%f"))
        except:
            pass

    if not all_ts:
        return df_tun, df_byp, pops, df_rtt, df_errs, steer

    reference = max(all_ts)
    cutoff    = reference - timedelta(minutes=minutes)

    # Apply filters
    df_tun = df_tun[df_tun["Timestamp"] >= cutoff] if "Timestamp" in df_tun.columns else df_tun
    df_byp = df_byp[df_byp["Timestamp"] >= cutoff] if "Timestamp" in df_byp.columns else df_byp
    pops   = [(ts, ln) for ts, ln in pops if ts >= cutoff]
    df_rtt = df_rtt[df_rtt["Timestamp"] >= cutoff] if "Timestamp" in df_rtt.columns else df_rtt
    df_errs= df_errs[df_errs["Timestamp"] >= cutoff] if "Timestamp" in df_errs.columns else df_errs

    filtered_steer = []
    for ln in steer:
        try:
            ts = datetime.strptime(ln[:23], "%Y/%m/%d %H:%M:%S.%f")
            if ts >= cutoff:
                filtered_steer.append(ln)
        except:
            filtered_steer.append(ln)

    return df_tun, df_byp, pops, df_rtt, df_errs, filtered_steer


# ─────────────────────────────────────────────────────────────────────────────
# NPADEBUGLOG PARSING
# ─────────────────────────────────────────────────────────────────────────────

def parse_npa_log_lines(lines):
    """
    Parse an npadebuglog file into:
      tenant_url, rtt_events, df_err, df_warn,
      tunnel_events, policy_records
    """
    tenant_url    = None
    rtt_events    = []
    errs          = []
    warns         = []
    tunnel_events = []
    policies      = []

    prefix_re  = re.compile(
        r'^\[(?P<host>[^:]+):'
        r'(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+) [+\-]\d{2}:\d{2}\]\s*'
    )
    re_tenant  = re.compile(r'[sS]et tenant url\s+(?P<tenant>\S+)\.?')
    re_err     = re.compile(r'\[(?:err|error)\]\s*(?P<msg>.+)', re.IGNORECASE)
    re_warn    = re.compile(r'\[(?:warn|warning)\]\s*(?P<msg>.+)', re.IGNORECASE)
    re_tun     = re.compile(r'Tunneling flow', re.IGNORECASE)
    re_pol     = re.compile(
        r'policy\.cpp:\d+:buildImpl\(\):.*Adding Host Rule',
        re.IGNORECASE
    )
    # New NPA RTT regex
    re_npa_rtt = re.compile(
        r'GW FQDN\s*=\s*([^,]+),\s*IP\s*=\s*([^,]+),\s*POP\s*=\s*([^,]+),\s*RTT\s*=\s*(\d+)\s*ms',
        re.IGNORECASE
    )

    collecting = False
    current    = {}

    for raw in lines:
        m = prefix_re.match(raw)
        if m:
            host = m.group("host")
            ts   = datetime.strptime(m.group("ts"), "%Y-%m-%d %H:%M:%S.%f")
            rest = raw[m.end():].strip()
        else:
            host, ts, rest = None, None, raw.strip()

        # Tenant
        if tenant_url is None:
            m2 = re_tenant.search(rest)
            if m2:
                tenant_url = m2.group("tenant")

        # Errors & Warnings
        m2 = re_err.search(raw)
        if m2:
            errs.append({"Timestamp": ts, "Message": raw.strip()})
        m2 = re_warn.search(raw)
        if m2:
            warns.append({"Timestamp": ts, "Message": raw.strip()})

        # NPA-style RTT
        m_rtt = re_npa_rtt.search(rest)
        if m_rtt:
            rtt_events.append(rest)
            continue

        # Generic RTT fallback
        if "RTT" in rest and "HIST" not in rest:
            rtt_events.append(rest)
            continue

        # Tunnel
        if re_tun.search(rest):
            tunnel_events.append(rest)
            continue

        # Policy start
        if re_pol.search(rest):
            collecting = True
            current = {"Hostname": host, "Timestamp": ts, "Publishers": None}
            continue

        # Policy block
        if collecting:
            if rest.startswith("Policy Name:"):
                current["Policy Name"] = rest.split(":", 1)[1].strip()
            elif rest.startswith("App Name:"):
                current["App Name"] = rest.split(":", 1)[1].strip()
            elif rest and rest[0].isdigit():
                current["App Details"] = rest
            elif rest.startswith("Publishers:"):
                current["Publishers"] = rest.split(":", 1)[1].strip()
                policies.append(current)
                collecting = False
            continue

    df_err  = pd.DataFrame(errs)
    df_warn = pd.DataFrame(warns)

    return tenant_url, rtt_events, df_err, df_warn, tunnel_events, policies


def filter_npa_by_minutes(
    tenant_url, rtt_events, df_err, df_warn, tunnel_events, policy_records, minutes
):
    """
    Filter npadebuglog entries to only those from the last `minutes` minutes
    (relative to the latest timestamp in the log).
    """
    # Collect timestamps
    all_ts = []
    if not df_err.empty:
        all_ts.append(df_err["Timestamp"].max())
    for ln in rtt_events + tunnel_events:
        m = re.match(r'^\[.*:(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)', ln)
        if m:
            all_ts.append(datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S.%f"))
    for p in policy_records:
        if p.get("Timestamp"):
            all_ts.append(p["Timestamp"])

    if not all_ts:
        df_all = pd.concat([df_err, df_warn], ignore_index=True)
        return tenant_url, rtt_events, df_all, tunnel_events, policy_records

    reference = max(all_ts)
    cutoff    = reference - timedelta(minutes=minutes)

    # Filter RTT
    filtered_rtt = []
    for ln in rtt_events:
        m = re.match(r'^\[.*:(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)', ln)
        if m and datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S.%f") < cutoff:
            continue
        filtered_rtt.append(ln)

    # Combine & filter errors/warnings
    df_all = pd.concat([df_err, df_warn], ignore_index=True)
    if "Timestamp" in df_all.columns:
        df_all = df_all[df_all["Timestamp"] >= cutoff]

    # Filter tunnels
    filtered_tun = []
    for ln in tunnel_events:
        m = re.match(r'^\[.*:(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)', ln)
        if m and datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S.%f") < cutoff:
            continue
        filtered_tun.append(ln)

    # Filter policies
    filtered_pols = [
        p for p in policy_records
        if p.get("Timestamp") and p["Timestamp"] >= cutoff
    ]

    return tenant_url, filtered_rtt, df_all, filtered_tun, filtered_pols


