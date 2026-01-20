# Rate Limiting & Error Handling

- HTTP 429 Too Many Requests: { "message": "Limit Exceeded" }.
- Implement exponential backoff or queueing in high-traffic environments.
- Fail-Open vs Fail-Closed:
  - Examples use fail-open (allow on API error) for availability.
  - For stricter security, fail-closed (block when API unavailable).
- Log API responses and outcomes for audit and tuning.
