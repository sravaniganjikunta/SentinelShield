# SentinelShield: Advanced Intrusion Detection & Web Protection System

## 1. Project Overview

**SentinelShield** is a student-level, rule-based web security system developed using **Python and Flask**. It acts as a lightweight web protection layer that inspects incoming HTTP requests, identifies common web-based attack patterns, blocks suspicious requests, and records security events in a log file.

The project demonstrates the basic working principles of an **Intrusion Detection/Prevention System (IDS/IPS)** and a lightweight **Web Application Firewall (WAF)**.

---

## 2. Objectives

The main objectives of SentinelShield are:

* Monitor incoming HTTP requests.
* Inspect request paths and query parameters.
* Detect common web attack patterns.
* Block malicious or suspicious requests.
* Allow legitimate requests to reach the application.
* Record security events in a log file.
* Analyze the generated security logs using **Splunk**.
* Demonstrate basic security monitoring and incident detection.

---

## 3. Technologies Used

| Technology           | Purpose                              |
| -------------------- | ------------------------------------ |
| Python               | Core programming language            |
| Flask                | Web application/server               |
| Rule-Based Detection | Attack identification                |
| HTML/HTTP Requests   | Web request testing                  |
| Linux/Ubuntu         | Development environment              |
| Splunk               | Security log analysis and monitoring |
| GitHub               | Project source-code repository       |

---

## 4. System Workflow

The basic workflow of SentinelShield is:

```text
Client Request
      ↓
Flask Server
      ↓
Request Inspection
      ↓
Attack Detection Rules
      ↓
 ┌───────────────┐
 │ Attack Found? │
 └───────┬───────┘
       Yes│       │No
          ↓       ↓
       BLOCK     ALLOW
          ↓       ↓
      Log Event  Log Event
          ↓       ↓
        Splunk Log Analysis
```

---

## 5. Attack Detection

SentinelShield was tested against the following common web attack categories:

### XSS Detection

The system inspects incoming request parameters for suspicious script-related patterns.

Example:

```text
/search?q=<script>alert("XSS")</script>
```

Expected result:

```text
Attack : XSS
Action : BLOCK
```

### SQL Injection Detection

The system checks requests for configured SQL injection patterns.

Example:

```text
/search?id=1' OR '1'='1
```

Expected result:

```text
Attack : SQL_INJECTION
Action : BLOCK
```

### Path Traversal Detection

The system checks for path traversal patterns attempting to access files outside the intended directory.

Example:

```text
/search?file=../../etc/passwd
```

Expected result:

```text
Attack : PATH_TRAVERSAL
Action : BLOCK
```

---

## 6. Legitimate Request Testing

Normal requests are allowed by the system.

Example:

```text
/search?q=hello
```

Expected result:

```text
Attack : NONE
Action : ALLOW
```

This demonstrates that the system distinguishes between normal and suspicious requests according to its configured rules.

---

## 7. Logging

When a request is processed, SentinelShield records relevant security information in:

```text
logs/sentinelshield.log
```

The log contains information such as:

```text
timestamp
source IP
HTTP method
request path
query
detected attack
action
```

Example:

```text
timestamp=... src_ip=127.0.0.1 method=GET path=/search query="q=hello" attack=NONE action=ALLOW
```

Blocked requests are also recorded with their detected attack type and blocking action.

---

## 8. Splunk Integration

The generated SentinelShield log file was analyzed using **Splunk**.

Splunk was used to:

* Search SentinelShield security events.
* Analyze allowed and blocked requests.
* Identify detected attack types.
* Monitor security activity.
* Create visual security monitoring dashboards.

This demonstrates how application security logs can be integrated with a **SIEM platform** for security monitoring and analysis.

---

## 9. Testing

The system was tested locally using a Flask development server.

The following security scenarios were tested:

| Test Case              | Expected Action |
| ---------------------- | --------------- |
| Normal request         | ALLOW           |
| XSS request            | BLOCK           |
| SQL Injection request  | BLOCK           |
| Path Traversal request | BLOCK           |

The testing confirmed that the configured rules identify and block the tested attack patterns.

---

## 10. Project Structure

```text
SentinelShield/
│
├── app.py
├── requirements.txt
├── README.md
│
├── logs/
│   └── sentinelshield.log
│
└── screenshots/
    ├── flask_server.png
    ├── xss_blocked.png
    ├── sql_injection_blocked.png
    └── path_traversal_blocked.png
```

> The `venv/` virtual environment folder should not be uploaded to GitHub.

---

## 11. Installation and Setup

### Step 1: Clone the Repository

```bash
git clone <YOUR-GITHUB-REPOSITORY-LINK>
cd SentinelShield
```

### Step 2: Create a Virtual Environment

```bash
python3 -m venv venv
```

### Step 3: Activate the Virtual Environment

```bash
source venv/bin/activate
```

### Step 4: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 5: Run the Flask Application

```bash
python3 app.py
```

The application runs locally at:

```text
http://127.0.0.1:5000
```

---

## 12. Example Testing URLs

### Normal Request

```text
http://127.0.0.1:5000/search?q=hello
```

Result:

```text
ALLOW
```

### XSS Test

```text
http://127.0.0.1:5000/search?q=<script>alert("XSS")</script>
```

Result:

```text
BLOCK
```

### SQL Injection Test

```text
http://127.0.0.1:5000/search?id=1' OR '1'='1
```

Result:

```text
BLOCK
```

### Path Traversal Test

```text
http://127.0.0.1:5000/search?file=../../etc/passwd
```

Result:

```text
BLOCK
```

---

## 13. Results

SentinelShield successfully demonstrated:

* HTTP request inspection.
* Rule-based attack detection.
* XSS detection and blocking.
* SQL Injection detection and blocking.
* Path Traversal detection and blocking.
* Security event logging.
* Splunk-based log analysis.
* Basic security monitoring using a dashboard.

---

## 14. Limitations

* This is a student-level, rule-based implementation.
* Detection depends on the configured attack signatures and rules.
* The system was tested in a local Flask environment.
* It is not intended to be used as a production-grade WAF.

---

## 15. Future Scope

Possible future improvements include:

* Adding more attack detection rules.
* Improving detection accuracy.
* Adding authentication and access control.
* Adding real-time alert notifications.
* Expanding Splunk dashboards.
* Adding more detailed incident-response features.
* Using machine-learning-based anomaly detection.
* Deploying the system in a controlled cloud environment.

---

## 16. Conclusion

SentinelShield demonstrates the basic principles of web application protection by inspecting HTTP requests, detecting configured attack patterns, blocking suspicious requests, and recording security events.

The integration with Splunk demonstrates how security logs generated by a web protection system can be collected and analyzed for monitoring and investigation.

The project provides practical exposure to **Flask, web security, attack detection, logging, SIEM, and basic SOC workflows**.

---

## 17. Project Type

**Academic / Student Project**

**Domain:** Cybersecurity / Web Security / Intrusion Detection / SIEM

**Primary Technologies:** Python, Flask, Splunk, Linux
