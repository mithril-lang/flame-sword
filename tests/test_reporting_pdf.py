import pytest

from utils.reporting import ReportGenerator


def test_login_page_integer_status_renders_pdf_section():
    """Regression: an integer status/type crashed reportlab (Paragraph needs str)."""
    generator = ReportGenerator()
    scan_results = {
        'domain': 'example.invalid',
        'email_enumeration': {
            'email_formats': [{'pattern': 'first.last', 'example': 'a.b', 'confidence': 90}],
            'found_emails': [{'email': 'a.b@example.invalid', 'type': 'admin', 'confidence': 90}],
            'login_pages': [
                {'url': 'https://login.example.invalid', 'type': 'http_login', 'status': 200},
                {'url': 'https://app.example.invalid/admin', 'type': 'form', 'status': 401},
            ],
        },
    }
    elements = generator._create_retro_email_enumeration(scan_results)
    assert elements, "expected elements for the email enumeration section"


def test_full_pdf_build_with_int_status():
    """End-to-end: generate_pdf must not raise on integer login-page fields."""
    generator = ReportGenerator()
    scan_results = {
        'domain': 'example.invalid',
        'subdomains': [
            {'subdomain': 'example.invalid', 'http_status': None, 'https_status': 200},
        ],
        'email_enumeration': {
            'login_pages': [{'url': 'https://login.example.invalid', 'type': 'http_login', 'status': 200}],
        },
    }
    pdf = generator.generate_pdf(scan_results)
    assert pdf.startswith(b'%PDF')
