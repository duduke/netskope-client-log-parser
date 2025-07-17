import os
import tempfile
import io
import zipfile
from flask import Flask, request, render_template, send_file
from collections import defaultdict
import pandas as pd

from parser_utils import (
    parse_log_lines,
    parse_npa_log_lines,
    filter_ns_by_minutes,
    filter_npa_by_minutes,
)

app = Flask(__name__)
UPLOAD_FOLDER = tempfile.gettempdir()


def group_by_process_and_host(df: pd.DataFrame):
    grouped = defaultdict(lambda: defaultdict(int))
    if "Process" in df.columns and "Destination Host" in df.columns:
        for _, row in df.iterrows():
            proc = row["Process"]
            host = row["Destination Host"]
            grouped[proc][host] += 1
    return grouped


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "GET":
        return render_template("index.html")

    upload = request.files.get("logfile")
    if not upload or not upload.filename:
        return render_template("index.html", error="No file uploaded!")

    fn = upload.filename.lower()
    minutes = request.form.get("minutes")
    minutes = int(minutes) if minutes and minutes.isdigit() else None

    # Save + read
    path = os.path.join(UPLOAD_FOLDER, upload.filename)
    upload.save(path)
    with open(path, "r", errors="ignore") as fh:
        lines = fh.readlines()

    # Content sniffing
    is_npa = any("policy.cpp" in ln for ln in lines)
    is_ns  = any("stAgentSvc" in ln or "stAgentNE" in ln for ln in lines)

    # -- NSDEBUGLOG branch --
    if "nsdebuglog" in fn or (is_ns and not is_npa):
        msg = "nsdebuglog log file detected!"
        df_t, df_b, pops, df_r, df_e, steer, last_gw, hdr = parse_log_lines(lines)
        if minutes is not None:
            df_t, df_b, pops, df_r, df_e, steer = filter_ns_by_minutes(
                df_t, df_b, pops, df_r, df_e, steer, minutes
            )
        grouped_t = group_by_process_and_host(df_t)
        grouped_b = group_by_process_and_host(df_b)
        stats = {
            "Log": "NS Debug",
            "Span (min)": minutes or "All",
            "Errors": len(df_e),
            "Tunnels": len(df_t),
            "Bypasses": len(df_b),
        }

        # Save CSVs
        df_t.to_csv(os.path.join(UPLOAD_FOLDER, "tunneled.csv"), index=False)
        df_b.to_csv(os.path.join(UPLOAD_FOLDER, "bypassed.csv"), index=False)
        df_r.to_csv(os.path.join(UPLOAD_FOLDER, "rtt.csv"), index=False)
        df_e.to_csv(os.path.join(UPLOAD_FOLDER, "general_errors.csv"), index=False)

        return render_template(
            "results.html",
            log_type_message=msg,
            stats=stats,
            header=hdr,
            last_gateway=last_gw or "",
            pops=[ln for _, ln in pops[-5:]] if pops else [],
            df_rtt=df_r.to_html(classes="table table-sm", index=False),
            df_err=df_e.to_html(classes="table table-sm", index=False),
            steering=steer,
            tunneled=grouped_t,
            bypassed=grouped_b,
        )

    # -- NPADEBUGLOG branch --
    if "npadebuglog" in fn or is_npa:
        msg = "npadebuglog log file detected!"
        tenant, rtt_events, df_err, df_warn, tunnels, policies = parse_npa_log_lines(lines)

        if minutes is not None:
            tenant, rtt_events, df_all_errs, tunnels, policies = filter_npa_by_minutes(
                tenant, rtt_events, df_err, df_warn, tunnels, policies, minutes
            )
        else:
            df_all_errs = pd.concat([df_err, df_warn], ignore_index=True)

        stats = {
            "Log": "NPA Debug",
            "Errors": len(df_all_errs),
            "Tunnels": len(tunnels),
            "Apps": len(policies),
        }

        # Save CSVs
        pd.DataFrame(rtt_events, columns=["Event"]).to_csv(
            os.path.join(UPLOAD_FOLDER, "npa_rtt.csv"), index=False
        )
        df_all_errs.to_csv(os.path.join(UPLOAD_FOLDER, "npa_errors.csv"), index=False)

        return render_template(
            "npa_results.html",
            log_type_message=msg,
            stats=stats,
            tenant_url=tenant or "",
            rtt_events=rtt_events,
            error_table=df_all_errs.to_html(classes="table table-sm", index=False),
            tunnel_events=tunnels,
            policy_records=policies,
        )

    # -- Fallback --
    return render_template(
        "index.html",
        error="Could not detect log type—please upload a valid nsdebuglog or npadebuglog file."
    )


@app.route("/download/<datatype>")
def download(datatype):
    files = {
        "tunneled": "tunneled.csv",
        "bypassed": "bypassed.csv",
        "rtt": "rtt.csv",
        "general": "general_errors.csv",
        "npa_rtt": "npa_rtt.csv",
        "npa_errors": "npa_errors.csv",
    }
    fname = files.get(datatype)
    if not fname:
        return "File not found", 404
    path = os.path.join(UPLOAD_FOLDER, fname)
    if not os.path.exists(path):
        return "File not found", 404
    return send_file(path, as_attachment=True)


@app.route("/export_all")
def export_all():
    mem = io.BytesIO()
    with zipfile.ZipFile(mem, "w") as z:
        for name in (
            "tunneled.csv", "bypassed.csv", "rtt.csv", "general_errors.csv",
            "npa_rtt.csv", "npa_errors.csv"
        ):
            p = os.path.join(UPLOAD_FOLDER, name)
            if os.path.exists(p):
                z.write(p, arcname=name)
    mem.seek(0)
    return send_file(
        mem,
        download_name="all_logs.zip",
        as_attachment=True,
        mimetype="application/zip"
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
