# Security Scenarios

Toggle these per your policy and UX.

1. Block High/Extreme: Redirect or deny immediately for RiskScore in High, Extreme.
2. Quarantine Medium: Challenge Medium risk users via captcha/verification.
3. Strict Mode: Allow only Low risk or SearchEngineBot.
4. Block Proxies: Block when any of Proxy, VPN, TOR are true, except bots.
5. Block Anonymizers: Block Extreme or any anonymizer flags.
6. Geo-Blocking: Block when CountryCode in banned list.

Recommended order: evaluate from strictest to broadest; redirect early.
