"""Test UI Rendering and Brand Header Integrity for GOVNEXIS 3.0 (Flask).

Verifies that all 9 primary navigation pages render cleanly without raw template leakage
or unhandled exceptions.
"""

import re
import pytest
from app import create_app


@pytest.fixture
def client():
    app = create_app("development")
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


# Regex matching emoji character ranges (emoticons, pictographs, symbols, dingbats)
EMOJI_REGEX = re.compile(r"[\U0001F300-\U0001F9FF\U00002600-\U000026FF\U00002700-\U000027BF]")


@pytest.mark.parametrize("route,page_name", [
    ("/scan", "New Security Scan"),
    ("/overview", "Overview"),
    ("/findings", "Findings"),
    ("/remediation", "Remediation"),
    ("/verification", "Verification"),
    ("/history", "History"),
    ("/reports", "Reports"),
    ("/demo-lab", "Demo Lab"),
    ("/settings", "Settings"),
])
def test_page_renders_without_raw_markup_leaks(client, route, page_name):
    """Test that each page executes without exceptions and adheres to design system criteria."""
    response = client.get(route, follow_redirects=True)
    assert response.status_code == 200, f"Failed rendering {page_name} ({route}): {response.status_code}"

    html = response.data.decode("utf-8")

    # Verify no raw Jinja syntax leaks into the rendered DOM
    assert "{{" not in html, f"Unrendered Jinja tag leaked into rendered HTML on {page_name}"
    assert "{%" not in html, f"Unrendered Jinja block leaked into rendered HTML on {page_name}"

    # Verify core branding and navigation
    assert "GOVNEXIS" in html, f"Branding missing on {page_name}"
    assert "3.0" in html, f"Version 3.0 badge missing on {page_name}"

    # Design System: Default light mode enabled for first-time visitors
    assert 'data-theme="light"' in html, f"Light mode default missing on {page_name}"

    # Design System: Theme switcher button present in navigation
    assert 'id="theme-toggle-btn"' in html, f"Theme switch button missing on {page_name}"

    # Design System: Official GOVNEXIS project logo in header
    assert "govnexis_logo.png" in html, f"GOVNEXIS official logo missing on {page_name}"

    # Design System: NEXION creator team logo present in footer/about
    assert "nexion_logo.png" in html, f"NEXION team logo reference missing on {page_name}"

    # Scoring standard: Exclusively CVSS v3.0
    assert "CVSS v3.0" in html, f"CVSS v3.0 standard reference missing on {page_name}"

    # Design System: Strictly zero emojis across interface
    emoji_matches = EMOJI_REGEX.findall(html)
    assert not emoji_matches, f"Emoji characters found in {page_name}: {emoji_matches}"

