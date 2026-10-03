import math
import re


COMMON_PASSWORDS = {
    "password",
    "password123",
    "123456",
    "12345678",
    "123456789",
    "qwerty",
    "qwerty123",
    "admin",
    "admin123",
    "letmein",
    "welcome",
    "iloveyou",
}


def format_time(seconds):
    if seconds < 1:
        return "Instant"

    elif seconds < 60:
        return f"{seconds:.1f} seconds"

    elif seconds < 3600:
        return f"{seconds / 60:.1f} minutes"

    elif seconds < 86400:
        return f"{seconds / 3600:.1f} hours"

    elif seconds < 31557600:
        return f"{seconds / 86400:.1f} days"

    elif seconds < 31557600 * 100:
        return f"{seconds / 31557600:.1f} years"

    else:
        return "Centuries"


def check_password(password):

    score = 0
    feedback = []

    # Empty password
    if not password:
        return {
            "score": 0,
            "strength": "Very Weak",
            "feedback": ["Enter a password to begin the analysis."],
            "crack_time": "Instant",
            "entropy": 0,
            "common_password": False,
            "patterns": []
        }

    password_lower = password.lower()

    # -----------------------------
    # Common password detection
    # -----------------------------

    common_password = password_lower in COMMON_PASSWORDS

    if common_password:
        feedback.append(
            "This password is commonly used and should be avoided."
        )

    # -----------------------------
    # Character analysis
    # -----------------------------

    has_lowercase = bool(re.search(r"[a-z]", password))
    has_uppercase = bool(re.search(r"[A-Z]", password))
    has_number = bool(re.search(r"\d", password))
    has_special = bool(re.search(r"[^A-Za-z0-9]", password))

    charset_size = 0

    if has_lowercase:
        score += 1
        charset_size += 26
    else:
        feedback.append("Add lowercase letters.")

    if has_uppercase:
        score += 1
        charset_size += 26
    else:
        feedback.append("Add uppercase letters.")

    if has_number:
        score += 1
        charset_size += 10
    else:
        feedback.append("Add numbers.")

    if has_special:
        score += 1
        charset_size += 32
    else:
        feedback.append("Add special characters.")

    # -----------------------------
    # Length
    # -----------------------------

    if len(password) >= 8:
        score += 1
    else:
        feedback.append("Use at least 8 characters.")

    if len(password) >= 12:
        score += 1

    if len(password) >= 16:
        feedback.append("Good length — 16+ characters provides additional protection.")

    # -----------------------------
    # Repeated characters
    # -----------------------------

    repeated_pattern = bool(
        re.search(r"(.)\1\1", password)
    )

    if repeated_pattern:
        feedback.append(
            "Avoid repeating the same character three or more times."
        )

    # -----------------------------
    # Sequential patterns
    # -----------------------------

    sequential_patterns = [
        "1234",
        "2345",
        "3456",
        "4567",
        "5678",
        "6789",
        "abcd",
        "bcde",
        "cdef",
        "qwer",
        "asdf",
    ]

    found_patterns = []

    for pattern in sequential_patterns:
        if pattern in password_lower:
            found_patterns.append(pattern)

    if found_patterns:
        feedback.append(
            "Avoid predictable sequences such as numbers or keyboard patterns."
        )

    # -----------------------------
    # Entropy / crack-time estimate
    # -----------------------------

    if charset_size == 0:

        entropy = 0
        crack_time = "Instant"

    else:

        entropy = len(password) * math.log2(charset_size)

        # Educational offline brute-force assumption.
        guesses_per_second = 10_000_000_000

        average_guesses = (2 ** entropy) / 2

        seconds = average_guesses / guesses_per_second

        crack_time = format_time(seconds)

    # -----------------------------
    # Strength classification
    # -----------------------------

    if common_password:
        strength = "Very Weak"

    elif score <= 2:
        strength = "Weak"

    elif score <= 4:
        strength = "Moderate"

    elif score == 5:
        strength = "Strong"

    else:
        strength = "Very Strong"

    # -----------------------------
    # Final recommendation
    # -----------------------------

    if len(password) >= 12 and not feedback:
        feedback.append(
            "Excellent! This password meets the basic strength checks."
        )

    return {
        "score": score,
        "strength": strength,
        "feedback": feedback,
        "crack_time": crack_time,
        "entropy": round(entropy, 1),
        "common_password": common_password,
        "patterns": found_patterns
    }