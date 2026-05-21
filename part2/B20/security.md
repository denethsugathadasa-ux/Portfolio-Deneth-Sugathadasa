# Security Policy

## Supported Versions
Only the latest version of this project is actively maintained and supported.

## Security Measures
The following security controls are implemented in this application:

- Passwords hashed using bcrypt
- Parameterised SQL queries to prevent SQL injection
- Secret key loaded from environment variables (never hardcoded)
- Debug mode disabled in production
- Rate limiting on login endpoint (5 attempts per minute per IP)
- HTTP security headers enforced on all responses:
  - X-Frame-Options: DENY
  - X-Content-Type-Options: nosniff
  - X-XSS-Protection: 1; mode=block
  - Strict-Transport-Security: max-age=31536000
  - Content-Security-Policy: default-src 'self'
- Input length validation on all user-supplied fields
- All login attempts logged with IP address

## Reporting a Vulnerability
If you discover a vulnerability in this project please open a GitHub issue 
or contact the repository owner directly. Do not publicly disclose 
vulnerabilities before they have been patched.

Do not include sensitive information such as credentials or private data 
in vulnerability reports.