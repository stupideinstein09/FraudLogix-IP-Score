# Implementation Guide

## Get an API Key
- Request/obtain x-api-key for iplist.fraudlogix.com.
- Keep keys in env vars, secrets managers, or server config.

## Integration Steps
1. Identify protected routes/pages.
2. Insert middleware/decorator/security check at the top.
3. Configure scenario toggles and banned countries.
4. Decide fail-open vs fail-closed behavior.
5. Log decisions (allow/challenge/block) with IP and reason.

## Deployment Tips
- Cache low-risk decisions briefly to reduce API calls.
- Rate-limit per IP and per route to avoid spikes.
- Provide friendly blocked/verify pages with support contact.
- Respect privacy and legal requirements.
