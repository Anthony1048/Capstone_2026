import html
import json
import os
import sys

# When frozen as a PyInstaller exe, __file__ is unreliable
# Use sys.executable to get the actual exe location instead
if getattr(sys, 'frozen', False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def build_report(json_input, template_input, output_path):
    try:
        # Load the stylesheet from the html folder to embed into the final report
        with open(os.path.join(BASE_DIR, '..', 'html', 'style.css'), 'r') as c:
            css_content = c.read()
        # Load the scan results JSON produced by scanner
        with open(json_input, 'r') as f:
            data = json.load(f)

        # 1. Initialize severity counters and HTML string accumulators
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        findings_html = ""
        statuses_html = ""

        # 1b. Build the security feature status list HTML
        # Each status gets a color-coded row based on Pass/Fail/Error
        STATUS_STYLES = {
            "Pass":  {"color": "#388e3c", "bg": "#e8f5e9", "icon": "&#10003;"},
            "Fail":  {"color": "#d32f2f", "bg": "#ffebee", "icon": "&#10007;"},
            "Error": {"color": "#e65100", "bg": "#fff3e0", "icon": "&#9888;"},
        }
        for s in data.get('statuses', []):
            s_status = s.get('status', 'Error')
            style = STATUS_STYLES.get(s_status, STATUS_STYLES["Error"])
            s_name = html.escape(s.get('name', ''))
            s_desc = html.escape(s.get('description', ''))
            statuses_html += f"""
            <div style="display:flex;align-items:center;padding:10px 14px;margin-bottom:8px;border-radius:6px;background:{style['bg']};border-left:4px solid {style['color']};">
                <span style="color:{style['color']};font-size:1.2em;font-weight:bold;margin-right:10px;">{style['icon']}</span>
                <div>
                    <strong style="color:{style['color']};">{s_status}</strong>
                    &mdash; <strong>{s_name}</strong>: {s_desc}
                </div>
            </div>
            """
        if not statuses_html:
            statuses_html = "<p>No status data available.</p>"

        # 2. Loop through findings to count by severity and build findings HTML
        for item in data.get('findings', []):
            raw_sev = item.get('severity', 'Low')
            sev = raw_sev.capitalize()
            if sev in counts:
                counts[sev] += 1

            # Escape all user-facing strings to prevent XSS in the report
            f_name = html.escape(item.get('name', 'Unknown Check'))
            f_desc = html.escape(item.get('description', 'No description provided.'))
            f_evid = html.escape(item.get('evidence', 'N/A'))
            f_reme = html.escape(item.get('remediation', 'No remediation guidance available.'))

            findings_html += f"""
            <div class="finding-item {sev}">
                <div class="finding-header">
                   <h3 style="margin:0;">{f_name}</h3>
                   <span class="badge {sev}">{sev}</span>
                </div>
                <div class="finding-body">
                    <p>{f_desc}</p>
                    <strong>Technical Evidence:</strong>
                    <code>{f_evid}</code>
                    <div class="remediation-box">
                        <strong>Remediation Guidance:</strong>
                        <p>{f_reme}</p>
                    </div>
                </div>
            </div>
            """

        # 3. Calculate overall risk level based on highest severity present
        risk_level = "Secure"
        risk_color = "#388e3c"
        if counts['Critical'] > 0:
            risk_level = "Critical Risk"
            risk_color = "#d32f2f"
        elif counts['High'] > 0:
            risk_level = "High Risk"
            risk_color = "#ef6c00"

        # 4. Build the scan summary HTML block (total findings + severity badge counts)
        status_html = f"""
        <div class="status-summary">
            <p><strong>Total Findings:</strong> {len(data.get('findings', []))}</p>
            <p><strong>Risk Level:</strong> <span style="color:{risk_color}; font-weight:bold;">{risk_level}</span></p>
            <hr style="border:0; border-top:1px solid #ddd; margin:10px 0;">
            <span class="badge Critical">{counts['Critical']} Critical</span>
            <span class="badge High">{counts['High']} High</span>
            <span class="badge Medium">{counts['Medium']} Medium</span>
            <span class="badge Low">{counts['Low']} Low</span>
        </div>
        """

        # 5. Build system info HTML, converting timestamp from UTC to EDT for display
        system = data.get('system', {})
        from datetime import datetime, timezone, timedelta
        try:
            _ts = data.get('scan_timestamp', 'N/A')
            # Convert UTC ISO timestamp to EDT (UTC-4)
            _dt = datetime.fromisoformat(_ts).astimezone(timezone(timedelta(hours=-4)))
            analysis_date = _dt.strftime('%Y-%m-%d %H:%M:%S EDT')
        except Exception:
            # Fallback: strip timezone and microseconds, replace T separator
            analysis_date = str(data.get('scan_timestamp', 'N/A'))[:19].replace('T', ' ')
        sys_html = f"""
        <p><strong>Hostname:</strong> {html.escape(str(system.get('hostname', 'N/A')))}</p>
        <p><strong>OS:</strong> {html.escape(str(system.get('windows_version', 'N/A')))}</p>
        <p><strong>CPU:</strong> {html.escape(str(system.get('cpu', 'N/A')))}</p>
        <p><strong>RAM:</strong> {html.escape(str(system.get('ram', 'N/A')))}</p>
        <p><strong>Storage (C:):</strong> {html.escape(str(system.get('disk', 'N/A')))}</p>
        <p><strong>GPU:</strong> {html.escape(str(system.get('gpu', 'N/A')))}</p>
        <p><strong>Analysis Date:</strong> {html.escape(analysis_date)}</p>
        """

        # Load the HTML template and inject the stylesheet inline
        # (so the report is fully self-contained with no external CSS dependency)
        with open(template_input, 'r') as t:
            template = t.read()

        template = template.replace('<link rel="stylesheet" href="style.css">', f'<style>{css_content}</style>')
        # Replace template placeholders with generated HTML sections
        final_report = template.replace('{{SYSTEM_INFO}}', sys_html)
        final_report = final_report.replace('{{SCAN_STATUS}}', status_html)
        final_report = final_report.replace('{{STATUSES}}', statuses_html)
        final_report = final_report.replace('{{FINDINGS}}', findings_html)

        # Write the completed report to the output path
        with open(output_path, 'w') as out:
            out.write(final_report)
        print(f"Report successfully generated at: {output_path}")

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    # Accept command line args: json_input, template, output_path
    # Falls back to defaults if run directly without arguments
    if len(sys.argv) == 4:
        build_report(sys.argv[1], sys.argv[2], sys.argv[3])
    else:
        build_report('dummy_result.json', 'html/Capstone.html', 'generated reports/final_report.html')
