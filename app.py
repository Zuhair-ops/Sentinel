import os
from flask import Flask, render_template, request
from werkzeug.exceptions import RequestEntityTooLarge
from utils.password_checker import check_password
from utils.log_manager import get_logs, add_log
from utils.hash_checker import calculate_hashes, verify_hash
from utils.url_checker import check_url

app = Flask(__name__)
# Security configuration
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16 MB upload limit

@app.route("/")
def home():

    logs = get_logs()

    total_scans = len(logs)

    url_scans = sum(
        1 for log in logs
        if log.get("action") == "URL Scan"
    )

    file_scans = sum(
        1 for log in logs
        if log.get("action") == "File Hash Scan"
    )

    security_events = sum(
    1 for log in logs
    if log.get("result") in [
        "MISMATCH",
        "Moderate",
        "Elevated",
        "Weak",
        "Very Weak"
    ]
)

    stats = {
        "total_scans": total_scans,
        "url_scans": url_scans,
        "file_scans": file_scans,
        "security_events": security_events
    }
    recent_logs=logs[-5:][::-1]  # Get the last 5 logs and reverse the order for display
    return render_template(
        "index.html",
        stats=stats,
        recent_logs=recent_logs
    )


@app.route("/password-checker", methods=["GET", "POST"])
def password_checker():
    result = None

    if request.method == "POST":
        password = request.form.get("password", "")

        result = check_password(password)

        # Log the check without storing the password
        add_log(
            "Password Check",
            "Password",
            result["strength"]
        )

    return render_template(
        "password_checker.html",
        result=result
    )
@app.route("/hash-checker", methods=["GET", "POST"])
def hash_checker():

    result = None

    if request.method == "POST":

        uploaded_file = request.files.get("file")
        expected_hash = request.form.get("expected_hash", "").strip()

        if uploaded_file and uploaded_file.filename:

            hashes = calculate_hashes(uploaded_file)

            verification = verify_hash(
                hashes["sha256"],
                expected_hash
            )

            size = hashes["size"]

            if size < 1024:
                size_display = f"{size} bytes"

            elif size < 1024 * 1024:
                size_display = f"{size / 1024:.2f} KB"

            else:
                size_display = f"{size / (1024 * 1024):.2f} MB"

            result = {
                "filename": uploaded_file.filename,
                "size": size_display,
                "sha256": hashes["sha256"],
                "sha512": hashes["sha512"],
                "md5": hashes["md5"],
                "expected_hash": expected_hash,
                "verification": verification
            }
            if verification is True:
                log_result = "MATCH"
            elif verification is False:
                log_result = "MISMATCH"
            else:
                log_result = "No verification"

        add_log(
            "File Hash Scan",
            uploaded_file.filename,
            log_result
        )

    return render_template(
        "hash_checker.html",
        result=result
    )
@app.route("/url-security", methods=["GET", "POST"])
def url_security():

    result = None

    if request.method == "POST":

        url = request.form.get("url", "")

        result = check_url(url)
        if result.get("valid"):
            add_log(
    "URL Scan",
    result["url"],
    result["risk"]
)
          

    return render_template(
        "url_security.html",
        result=result
    )
@app.route("/security-logs")
def security_logs():

    logs = get_logs()

    return render_template(
        "security_logs.html",
        logs=logs
    )
@app.errorhandler(RequestEntityTooLarge)
def handle_file_too_large(error):
    return """
    <h2>⚠️ File Too Large</h2>
    <p>Sentinel only accepts files up to 16 MB.</p>
    <p><a href="/hash-checker">← Back to Hash Checker</a></p>
    """, 413

if __name__ == "__main__":

    debug_mode = os.environ.get(
        "SENTINEL_DEBUG",
        "true"
    ).lower() == "true"

    app.run(debug=debug_mode)



