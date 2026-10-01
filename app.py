from flask import Flask, request
from datetime import datetime
import os
import re

app = Flask(__name__)

# ============================================================
# CONFIGURATION
# ============================================================

LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "sentinelshield.log")

# Make sure logs directory exists
os.makedirs(LOG_DIR, exist_ok=True)


# ============================================================
# ATTACK DETECTION
# ============================================================

def detect_attack(query):

    # --------------------------------------------------------
    # XSS Detection
    # --------------------------------------------------------

    xss_patterns = [
        r"<script.*?>.*?</script>",
        r"<script",
        r"javascript:",
        r"onerror\s*=",
        r"onload\s*=",
        r"onclick\s*="
    ]

    for pattern in xss_patterns:
        if re.search(pattern, query, re.IGNORECASE):
            return "XSS"


    # --------------------------------------------------------
    # SQL Injection Detection
    # --------------------------------------------------------

    sql_patterns = [
        r"'\s*or\s*['\"]?\d+['\"]?\s*=\s*['\"]?\d+",
        r"'\s*or\s*1\s*=\s*1",
        r"union\s+select",
        r"\bdrop\s+table\b",
        r"\bselect\s+.*\s+from\b",
        r"--\s*$"
    ]

    for pattern in sql_patterns:
        if re.search(pattern, query, re.IGNORECASE):
            return "SQL_INJECTION"


    # --------------------------------------------------------
    # Path Traversal Detection
    # --------------------------------------------------------

    path_patterns = [
        r"\.\./",
        r"\.\.\\",
        r"%2e%2e%2f",
        r"%2e%2e%5c"
    ]

    for pattern in path_patterns:
        if re.search(pattern, query, re.IGNORECASE):
            return "PATH_TRAVERSAL"


    # --------------------------------------------------------
    # Command Injection Detection
    # --------------------------------------------------------

    command_patterns = [
        r";\s*(whoami|id|ls|pwd|cat)\b",
        r"\|\s*(whoami|id|ls|pwd|cat)\b",
        r"&&\s*(whoami|id|ls|pwd|cat)\b"
    ]

    for pattern in command_patterns:
        if re.search(pattern, query, re.IGNORECASE):
            return "COMMAND_INJECTION"


    # No attack detected
    return "NONE"


# ============================================================
# SEVERITY
# ============================================================

def get_severity(attack):

    if attack == "NONE":
        return "INFO"

    elif attack == "XSS":
        return "HIGH"

    elif attack == "SQL_INJECTION":
        return "CRITICAL"

    elif attack == "PATH_TRAVERSAL":
        return "HIGH"

    elif attack == "COMMAND_INJECTION":
        return "CRITICAL"

    else:
        return "MEDIUM"


# ============================================================
# LOGGING
# ============================================================

def write_log(attack, action):

    timestamp = datetime.now().isoformat()

    src_ip = request.remote_addr

    method = request.method

    path = request.path

    query = request.query_string.decode(
        "utf-8",
        errors="replace"
    )

    severity = get_severity(attack)

    # --------------------------------------------------------
    # Generate Alert ID
    # --------------------------------------------------------

    if not hasattr(write_log, "alert_number"):
        write_log.alert_number = 0

    write_log.alert_number += 1

    alert_id = f"SS-{write_log.alert_number:05d}"


    # --------------------------------------------------------
    # Create Log Entry
    # --------------------------------------------------------

    log_entry = (
        f"timestamp={timestamp} "
        f"alert_id={alert_id} "
        f"src_ip={src_ip} "
        f"method={method} "
        f"path={path} "
        f'query="{query}" '
        f"attack={attack} "
        f"severity={severity} "
        f"action={action}\n"
    )


    # --------------------------------------------------------
    # Save Log
    # --------------------------------------------------------

    with open(LOG_FILE, "a") as log_file:
        log_file.write(log_entry)


    # --------------------------------------------------------
    # Display Log in Terminal
    # --------------------------------------------------------

    print("\n" + "=" * 70)
    print("SENTINELSHIELD SECURITY EVENT")
    print("=" * 70)
    print(f"Timestamp : {timestamp}")
    print(f"Alert ID  : {alert_id}")
    print(f"Source IP : {src_ip}")
    print(f"Method    : {method}")
    print(f"Path      : {path}")
    print(f"Query     : {query}")
    print(f"Attack    : {attack}")
    print(f"Severity  : {severity}")
    print(f"Action    : {action}")
    print(f"Log saved : {LOG_FILE}")
    print("=" * 70)


# ============================================================
# HOME / SEARCH ROUTE
# ============================================================

@app.route("/")
@app.route("/search")
def search():

    # Get q parameter
    query = request.args.get("q", "")

    # Detect attack
    attack = detect_attack(query)


    # --------------------------------------------------------
    # MALICIOUS REQUEST
    # --------------------------------------------------------

    if attack != "NONE":

        write_log(attack, "BLOCK")

        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>SentinelShield - Blocked</title>
        </head>

        <body>

            <h1>🚫 REQUEST BLOCKED</h1>

            <h2>SentinelShield Security System</h2>

            <p>
                <strong>Attack Detected:</strong>
                {attack}
            </p>

            <p>
                <strong>Action:</strong>
                BLOCK
            </p>

            <p>
                This request was blocked by SentinelShield.
            </p>

        </body>
        </html>
        """, 403


    # --------------------------------------------------------
    # NORMAL REQUEST
    # --------------------------------------------------------

    write_log("NONE", "ALLOW")

    return f"""
    <!DOCTYPE html>
    <html>

    <head>
        <title>SentinelShield</title>
    </head>

    <body>

        <h1>✅ REQUEST ALLOWED</h1>

        <h2>SentinelShield Security System</h2>

        <p>
            <strong>Search Query:</strong>
            {query}
        </p>

        <p>
            <strong>Action:</strong>
            ALLOW
        </p>

    </body>

    </html>
    """


# ============================================================
# START SERVER
# ============================================================

if __name__ == "__main__":
    print()
    print("=" * 70)
    print("        SENTINELSHIELD SECURITY SYSTEM")
    print("=" * 70)
    print()
    print("Server      : http://127.0.0.1:5000")
    print("Log File    : logs/sentinelshield.log")
    print()
    print("Detection:")
    print("  [+] XSS")
    print("  [+] SQL Injection")
    print("  [+] Path Traversal")
    print("  [+] Command Injection")
    print()
    print("Press CTRL+C to stop the server.")
    print("=" * 70)
    print()

    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=False
    )
