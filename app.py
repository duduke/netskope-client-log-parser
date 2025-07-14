import os
import tempfile
from flask import Flask, request, render_template, send_file
import pandas as pd
from collections import defaultdict
from parser_utils import parse_log_lines, filter_by_minutes

app = Flask(__name__)
UPLOAD_FOLDER = tempfile.gettempdir()

def group_by_process_and_host(df):
    grouped = defaultdict(lambda: defaultdict(int))
    for _, row in df.iterrows():
        grouped[row["Process"]][row["Destination Host"]] += 1
    return grouped

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        f      = request.files.get('logfile')
        mins   = request.form.get('minutes')
        mins   = int(mins) if mins and mins.isdigit() else None

        fn = (f.filename or "").lower()
        if 'nsdebuglog' in fn:
            log_type_message = 'nsdebuglog log file detected!'
        elif 'npadebuglog' in fn:
            log_type_message = 'npadebuglog log file detected!'
        else:
            log_type_message = 'invalid log file detected!'

        # Save and read
        path = os.path.join(UPLOAD_FOLDER, f.filename)
        f.save(path)
        with open(path, 'r', errors='ignore') as fh:
            lines = fh.readlines()

        # Parse
        df_t, df_b, pops, df_rtt, df_err, steering, last_gw, hdr = parse_log_lines(lines)

        # Filter by minutes
        if mins:
            df_t, df_b, pops, df_rtt, df_err, steering = filter_by_minutes(
                df_t, df_b, pops, df_rtt, df_err, steering, mins
            )

        # Group counts
        g_t = group_by_process_and_host(df_t)
        g_b = group_by_process_and_host(df_b)

        # Save CSVs
        df_t.to_csv(os.path.join(UPLOAD_FOLDER, 'tunneled.csv'), index=False)
        df_b.to_csv(os.path.join(UPLOAD_FOLDER, 'bypassed.csv'), index=False)
        df_rtt.to_csv(os.path.join(UPLOAD_FOLDER, 'rtt.csv'), index=False)
        df_err.to_csv(os.path.join(UPLOAD_FOLDER, 'general_errors.csv'), index=False)

        return render_template(
            'results.html',
            log_type_message=log_type_message,
            hostname=hdr.get('hostname',''),
            os_version=hdr.get('os_version',''),
            client_version=hdr.get('client_version',''),
            tenant=hdr.get('tenant',''),
            last_gateway=last_gw or "",
            pops=[ln for _, ln in pops[-5:]],
            rtt_table=df_rtt.to_html(classes='table table-striped', index=False),
            error_table=df_err.to_html(classes='table table-striped', index=False),
            steering_info=steering,
            tunneled_count=len(g_t),
            bypassed_count=len(g_b),
            grouped_tunneled=g_t,
            grouped_bypassed=g_b
        )

    # GET → show upload form
    return render_template('index.html')

@app.route('/download/<what>')
def download(what):
    files = {
        'tunneled': 'tunneled.csv',
        'bypassed': 'bypassed.csv',
        'rtt':      'rtt.csv',
        'errors':   'general_errors.csv'
    }
    fname = files.get(what)
    if fname:
        path = os.path.join(UPLOAD_FOLDER, fname)
        if os.path.exists(path):
            return send_file(path, as_attachment=True)
    return "File not found", 404

if __name__ == '__main__':
    # Listen on all interfaces for Docker
    app.run(host='0.0.0.0', port=5000, debug=True)
