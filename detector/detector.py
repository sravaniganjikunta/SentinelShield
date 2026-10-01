from urllib.parse import unquote


def detect_xss(request_text):

    # Decode URL-encoded characters
    decoded_text = unquote(request_text)

    # Convert to lowercase
    decoded_text = decoded_text.lower()

    xss_patterns = [
        "<script",
        "javascript:",
        "onerror=",
        "onload=",
        "<iframe"
    ]

    for pattern in xss_patterns:
        if pattern in decoded_text:
            return True

    return False
