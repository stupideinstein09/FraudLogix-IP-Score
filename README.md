# Fraudlogix IP Score – Multi-Language Security Examples

Comprehensive, runnable examples showing how to use the Fraudlogix IP Score API to evaluate visitor risk and take actions (block, challenge, or allow).

## Overview
- Use `https://iplist.fraudlogix.com/v5?ip=<IP>` with `x-api-key` to retrieve risk data.
- Implement 6 configurable security scenarios across PHP, Python, Node.js, Go, Java, C#, and Ruby.
- Includes rate limit handling (HTTP 429) and sensible failure defaults.

## Get an API Key
- Register a free account with 1,000 IP lookups at https://ipui.fraudlogix.com/register.
- After registering, use your `x-api-key` in requests to `iplist.fraudlogix.com`.
- Store keys in environment variables or secrets managers; avoid hardcoding.

## Security Scenarios
1. Block high/extreme risk outright
2. Quarantine medium risk for verification (captcha/2FA)
3. Strict mode: allow only low-risk visitors and known search-engine bots
4. Block proxies/VPN/TOR, allow search-engine bots
5. Block anonymizers or extreme cases
6. Geo-block by `CountryCode`

## Quick Start
- PHP: see examples/php/security.php
- Python (Flask): see examples/python/app.py
- Node.js (Express): see examples/javascript/app.js
- Go: see examples/go/main.go
- Java (Spring sample): see examples/java/FraudlogixSecurityInterceptor.java
- C# (.NET middleware): see examples/csharp/FraudlogixSecurityMiddleware.cs
- Ruby (Rails before_action): see examples/ruby/fraudlogix_security.rb

## Configuration
- Set your API key and scenario toggles inside each example.
- Prefer environment variables in production: `FRAUDLOGIX_API_KEY`, `BLOCKED_PAGE`, `CAPTCHA_PAGE`.

## Handling Limits & Errors
- Exceeding limits returns HTTP 429 with `{ "message": "Limit Exceeded" }`.
- Examples default to fail-open (allow access) when API errors occur; adjust per your policy.

## Documentation
- API fields: docs/API.md
- Security scenarios: docs/SecurityScenarios.md
- Rate limiting & error handling: docs/RateLimiting.md
- Implementation guide: docs/ImplementationGuide.md

## Disclaimer
- Replace placeholder keys and URLs.
- Implement proper logging, auditing, and user privacy compliance (GDPR/CCPA) in production.
