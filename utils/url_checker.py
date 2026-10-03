from urllib.parse import urlparse
import ipaddress
import re


def check_url(url):

    url = url.strip()

    if not url:
        return {
            "url": url,
            "valid": False,
            "risk": "Unknown",
            "score": 0,
            "indicators": ["No URL was provided."]
        }

    test_url = url

    # Add a scheme if one was not provided
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", test_url):
        test_url = "http://" + test_url

    try:
        parsed = urlparse(test_url)
    except ValueError:
        return {
            "url": url,
            "valid": False,
            "risk": "Unknown",
            "score": 0,
            "indicators": ["The URL could not be parsed."]
        }

    hostname = parsed.hostname

    if not hostname:
        return {
            "url": url,
            "valid": False,
            "risk": "Unknown",
            "score": 0,
            "indicators": ["Invalid URL or missing domain."]
        }

    indicators = []
    score = 0

    # ------------------------------------------------
    # HTTPS
    # ------------------------------------------------

    if parsed.scheme == "https":
        https = True
    else:
        https = False
        indicators.append("URL does not use HTTPS.")
        score += 1

    # ------------------------------------------------
    # IP ADDRESS
    # ------------------------------------------------

    is_ip = False
    is_private_ip = False

    try:
        ip = ipaddress.ip_address(hostname)
        is_ip = True
        is_private_ip = ip.is_private

        if is_private_ip:
            indicators.append(
                "URL uses a private/local IP address."
            )
        else:
            indicators.append(
                "URL uses an IP address instead of a domain name."
            )
            score += 2

    except ValueError:
        pass

    # ------------------------------------------------
    # USERNAME / PASSWORD IN URL
    # ------------------------------------------------

    if parsed.username or parsed.password:
        indicators.append(
            "URL contains embedded user information before the domain."
        )
        score += 2

    # ------------------------------------------------
    # PUNYCODE
    # ------------------------------------------------

    if any(part.lower().startswith("xn--")
           for part in hostname.split(".")):

        indicators.append(
            "Domain contains Punycode (xn--), which can represent "
            "internationalized characters."
        )
        score += 1

    # ------------------------------------------------
    # PORT
    # ------------------------------------------------

    try:
        port = parsed.port

        if port is not None:

            common_ports = {
                80,
                443,
                8080,
                8443
            }

            if port not in common_ports:
                indicators.append(
                    f"URL uses a non-standard port ({port})."
                )
                score += 1

    except ValueError:
        indicators.append("URL contains an invalid port.")
        score += 1

    # ------------------------------------------------
    # SUBDOMAINS
    # ------------------------------------------------

    domain_parts = hostname.split(".")

    if not is_ip and len(domain_parts) >= 5:
        indicators.append(
            "Domain contains an unusually high number of subdomains."
        )
        score += 1

    # ------------------------------------------------
    # URL SHORTENERS
    # ------------------------------------------------

    shorteners = {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "is.gd",
        "cutt.ly",
        "shorturl.at",
        "ow.ly",
        "buff.ly",
        "rebrand.ly"
    }

    if hostname.lower() in shorteners:
        indicators.append(
            "URL uses a known URL-shortening service."
        )
        score += 1

    # ------------------------------------------------
    # SUSPICIOUS CHARACTERS
    # ------------------------------------------------

    if "@" in url:
        indicators.append(
            "URL contains '@', which can obscure the actual destination."
        )
        score += 2

    if "\\" in url:
        indicators.append(
            "URL contains backslash characters."
        )
        score += 1

    # ------------------------------------------------
    # PERCENT ENCODING
    # ------------------------------------------------

    encoded_parts = re.findall(r"%[0-9a-fA-F]{2}", url)

    if len(encoded_parts) >= 4:
        indicators.append(
            "URL contains a large amount of percent-encoded data."
        )
        score += 1

    # ------------------------------------------------
    # URL LENGTH
    # ------------------------------------------------

    if len(url) > 150:
        indicators.append(
            "URL is unusually long."
        )
        score += 1

    # ------------------------------------------------
    # PATH DEPTH
    # ------------------------------------------------

    path_parts = [
        part for part in parsed.path.split("/")
        if part
    ]

    if len(path_parts) >= 6:
        indicators.append(
            "URL contains an unusually deep path."
        )
        score += 1

    # ------------------------------------------------
    # QUERY PARAMETERS
    # ------------------------------------------------

    if parsed.query:

        query_parameters = parsed.query.count("&") + 1

        if query_parameters >= 8:
            indicators.append(
                "URL contains a large number of query parameters."
            )
            score += 1

    # ------------------------------------------------
    # SUSPICIOUS DOMAIN PATTERN
    # ------------------------------------------------

    if not is_ip:

        if re.search(r"\d{4,}", hostname):
            indicators.append(
                "Domain contains an unusually long sequence of numbers."
            )
            score += 1

    # ------------------------------------------------
    # RISK LEVEL
    # ------------------------------------------------

    if score == 0:
        risk = "Low"

    elif score <= 2:
        risk = "Moderate"

    else:
        risk = "Elevated"

    # ------------------------------------------------
    # NO INDICATORS
    # ------------------------------------------------

    if not indicators:
        indicators.append(
            "No obvious structural indicators detected."
        )


    # ------------------------------------------------
    # INDICATOR EXPLANATIONS
    # ------------------------------------------------

        explanation_map = {

    "URL does not use HTTPS.": (
            "HTTPS encrypts traffic between the browser and the website. "
            "Its absence does not prove that a website is malicious, "
            "but sensitive information should generally not be sent "
            "over an unencrypted connection."
        ),

        "URL uses a private/local IP address.": (
            "Private IP addresses are normally used inside local networks "
            "rather than as publicly reachable website addresses. "
            "This can be legitimate for internal applications."
        ),

        "URL uses an IP address instead of a domain name.": (
            "Using an IP address is not automatically malicious, but it "
            "can make a destination harder for users to recognize and "
            "can occur in some phishing or temporary infrastructure."
        ),

        "URL contains embedded user information before the domain.": (
            "Credentials or user information embedded in a URL can make "
            "the actual destination harder to recognize and should be "
            "treated carefully."
        ),

        "Domain contains Punycode (xn--), which can represent internationalized characters.": (
            "Punycode is legitimate technology for internationalized "
            "domain names, but visually similar characters can sometimes "
            "be used to make a domain resemble another domain."
        ),

        "URL contains '@', which can obscure the actual destination.": (
            "In a URL, information before '@' can be interpreted as "
            "userinfo while the hostname appears after it. This can "
            "mislead users who do not inspect the complete URL."
        ),

        "URL contains backslash characters.": (
            "Backslashes are unusual in standard web URLs and may indicate "
            "an incorrectly formatted or intentionally unusual URL."
        ),

        "URL uses a known URL-shortening service.": (
            "URL shorteners hide the final destination behind a redirect. "
            "They are legitimate services, but the destination is less "
            "visible before the link is opened."
        ),

        "URL is unusually long.": (
            "Very long URLs can be legitimate, but excessive length may "
            "make the destination harder to inspect and can sometimes "
            "appear in tracking or deceptive links."
        ),

        "URL contains an unusually deep path.": (
            "Deep URL paths are not inherently malicious, but unusually "
            "complex paths can make a destination harder to inspect."
        ),

        "URL contains a large number of query parameters.": (
            "Many query parameters can be legitimate, but they can also "
            "make a URL difficult to inspect and understand."
        ),

        "Domain contains an unusually long sequence of numbers.": (
            "Long numeric sequences in domains are not automatically "
            "malicious, but they can be an additional structural indicator "
            "worth reviewing."
        ),

        "URL contains a large amount of percent-encoded data.": (
            "Percent encoding is normal in URLs, but unusually large "
            "amounts of encoded data can make the destination harder "
            "to inspect."
        ),


        "URL contains an invalid port.": (
            "The port component could not be interpreted as a valid "
            "network port."
        ),

        "No obvious structural indicators detected.": (
            "Sentinel did not detect any of its configured structural "
            "indicators. This does not guarantee that the website is safe."
        )
    }

    explanations = []

    for indicator in indicators:

        if indicator.startswith("URL uses a non-standard port ("):

            explanation = (
                "Web applications commonly use ports such as 80 or 443. "
                "Other ports can be legitimate, but unusual ports deserve "
                "additional review."
            )

        else:

            explanation = explanation_map.get(
                indicator,
                "This indicator was detected by Sentinel's structural analysis."
            )

        explanations.append(explanation)

        return {
        "url": url,
        "valid": True,
        "https": https,
        "domain": hostname,
        "risk": risk,
        "score": score, 
        "indicators": indicators,
        "explanations": explanations
    }