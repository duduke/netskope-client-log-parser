import os
import tempfile
from flask import Flask, request, render_template, send_file
import pandas as pd
from collections import defaultdict
from parser_utils import parse_log_lines, filter_by_minutes

app = Flask(__name__)
UPLOAD_FOLDER = tempfile.gettempdir()

def group_by_process_and_host(df, ip_column_name):
    grouped = defaultdict(lambda: defaultdict(list))
    for _, row in df.iterrows():
        proc = row['Process']
        host = row['Destination Host']
        ip = row[ip_column_name]
        ts = row['Timestamp']
        grouped[proc][host].append((ts, ip))
    return grouped

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        file = request.files['logfile']
        minutes = request.form.get('minutes')
        minutes = int(minutes) if minutes and minutes.isdigit() else None

        if file:
            filepath = os.path.join(UPLOAD_FOLDER, file.filename)
            file.save(filepath)

            with open(filepath, 'r') as f:
                lines = f.readlines()

            df_tunnel, df_bypass, pop_entries, df_rtt, df_generalerr, last_gateway, steering_modes, header_info = parse_log_lines(lines)

            if minutes is not None:
                df_tunnel, df_bypass, pop_entries, df_rtt, df_generalerr = filter_by_minutes(
                    df_tunnel, df_bypass, pop_entries, df_rtt, df_generalerr, minutes
                )

            df_tunnel.to_csv(os.path.join(UPLOAD_FOLDER, "tunneled.csv"), index=False)
            df_bypass.to_csv(os.path.join(UPLOAD_FOLDER, "bypassed.csv"), index=False)
            df_rtt.to_csv(os.path.join(UPLOAD_FOLDER, "rtt.csv"), index=False)
            df_generalerr.to_csv(os.path.join(UPLOAD_FOLDER, "general_errors.csv"), index=False)

            grouped_tunneled = group_by_process_and_host(df_tunnel, "Destination IP:Port")
            grouped_bypassed = group_by_process_and_host(df_bypass, "Destination IP")

            return render_template(
                'results.html',
                grouped_tunneled=grouped_tunneled,
                grouped_bypassed=grouped_bypassed,
                tunneled_count=len(grouped_tunneled),
                bypassed_count=len(grouped_bypassed),
                pops=[line for _, line in pop_entries[-5:]] if pop_entries else [],
                rtt=df_rtt.to_html(classes='table table-striped', index=False) if not df_rtt.empty else "<p>No RTT data found.</p>",
                generalerr=df_generalerr.to_html(classes='table table-striped', index=False) if not df_generalerr.empty else "<p>No general warnings/errors found.</p>",
                file_uploaded=True,
                hostname=header_info["hostname"],
                os_version=header_info["os_version"],
                client_version=header_info["client_version"],
                last_gateway=last_gateway,
                tenant=header_info["tenant"],
                steering_modes=steering_modes
            )

    return render_template('index.html')

@app.route('/download/<datatype>')
def download_csv(datatype):
    files = {
        "tunneled": "tunneled.csv",
        "bypassed": "bypassed.csv",
        "rtt": "rtt.csv",
        "general": "general_errors.csv"
    }
    if datatype in files:
        filepath = os.path.join(UPLOAD_FOLDER, files[datatype])
        if os.path.exists(filepath):
            return send_file(filepath, as_attachment=True)
    return "File not found", 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)