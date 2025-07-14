import os
import tempfile
from flask import Flask, request, render_template, send_file
import pandas as pd
from collections import defaultdict

from parser_utils import (
    parse_log_lines,
    filter_by_minutes,
    parse_npa_log_lines,
)

app = Flask(__name__)
UPLOAD_FOLDER = tempfile.gettempdir()


def group_by_process_and_host(df):
    grouped = defaultdict(lambda: defaultdict(int))
    for _, row in df.iterrows():
        proc = row["Process"]
        host = row["Destination Host"]
        grouped[proc][host] += 1
    return grouped


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "GET":
        return render_template("index.html")

    file = request.files.get("logfile")
    if not file:
        return render_template("index.html", log_type_message="No file uploaded!")

    filename = file.filename or ""
    fn_lower = filename.lower()
    minutes = request.form.get("minutes")
    minutes = int(minutes) if minutes and minutes.isdigit() else None

    # Save and read
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    file.save(filepath)
    with open(filepath, "r", errors="ignore") as fh:
        lines = fh.readlines()

    # ── NSDEBUGLOG.PARSER ───────────────────────────────────────────────────
    if "nsdebuglog" in fn_lower:
        log_type_message = "nsdebuglog log file detected!"
        (
            df_tunnel,
            df_bypass,
            pop_entries,
            df_rtt,
            df_errors,
            steering_records,
            last_gateway,
            header_info,
        ) = parse_log_lines(lines)

        if minutes:
            (
                df_tunnel,
                df_bypass,
                pop_entries,
                df_rtt,
                df_errors,
                steering_records,
            ) = filter_by_minutes(
                df_tunnel,
                df_bypass,
                pop_entries,
                df_rtt,
                df_errors,
                steering_records,
                minutes,
            )

        grouped_t = group_by_process_and_host(df_tunnel)
        grouped_b = group_by_process_and_host(df_bypass)

        df_tunnel.to_csv(os.path.join(UPLOAD_FOLDER, "tunneled.csv"), index=False)
        df_bypass.to_csv(os.path.join(UPLOAD_FOLDER, "bypassed.csv"), index=False)
        df_rtt.to_csv(os.path.join(UPLOAD_FOLDER, "rtt.csv"), index=False)
        df_errors.to_csv(
            os.path.join(UPLOAD_FOLDER, "general_errors.csv"), index=False
        )

        return render_template(
            "results.html",
            log_type_message=log_type_message,
            hostname=header_info.get("hostname", ""),
            os_version=header_info.get("os_version", ""),
            client_version=header_info.get("client_version", ""),
            tenant=header_info.get("tenant", ""),
            last_gateway=last_gateway or "",
            pops=[line for _, line in pop_entries[-5:]] if pop_entries else [],
            rtt_table=df_rtt.to_html(
                classes="table table-striped", index=False
            ),
            error_table=df_errors.to_html(
                classes="table table-striped", index=False
            ),
            steering_info=steering_records,
            tunneled_count=len(grouped_t),
            bypassed_count=len(grouped_b),
            grouped_tunneled=grouped_t,
            grouped_bypassed=grouped_b,
        )

    # ── NPADEBUGLOG.PARSER ──────────────────────────────────────────────────
    elif "npadebuglog" in fn_lower:
        log_type_message = "npadebuglog log file detected!"
        (
            tenant_url,
            df_rtt_npa,
            df_err_npa,
            df_warn_npa,
            tunnel_events,
            policy_records,
        ) = parse_npa_log_lines(lines)

        # Combine errors + warnings
        df_err_warn = pd.concat([df_err_npa, df_warn_npa]) \
                       .sort_values("Timestamp") \
                       .reset_index(drop=True)

        # Save CSVs
        df_rtt_npa.to_csv(os.path.join(UPLOAD_FOLDER, "npa_rtt.csv"), index=False)
        df_err_warn.to_csv(os.path.join(UPLOAD_FOLDER, "npa_errors.csv"), index=False)

        return render_template(
            "npa_results.html",
            log_type_message=log_type_message,
            tenant_url=tenant_url,
            rtt_table=df_rtt_npa.to_html(
                classes="table table-striped", index=False
            ),
            error_table=df_err_warn.to_html(
                classes="table table-striped", index=False
            ),
            tunnel_events=tunnel_events,
            policy_records=policy_records,
        )

    # ── Invalid file ────────────────────────────────────────────────────────
    else:
        return render_template(
            "index.html", log_type_message="invalid log file detected!"
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
    if fname:
        path = os.path.join(UPLOAD_FOLDER, fname)
        if os.path.exists(path):
            return send_file(path, as_attachment=True)
    return "File not found", 404


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
