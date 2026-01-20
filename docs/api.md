# Fraudlogix IP Score API Fields

Example JSON response:

```
{
  "IP": "10.20.30.40",
  "RecentlySeen": 27,
  "RiskScore": "Low",
  "MaskedDevices": true,
  "Proxy": false,
  "TOR": false,
  "VPN": false,
  "DataCenter": false,
  "SearchEngineBot": false,
  "AbnormalTraffic": false,
  "ASN": "19281",
  "Organization": "Quad9",
  "ISP": "Quad9",
  "City": "",
  "Country": "United States",
  "CountryCode": "US",
  "Region": "",
  "Timezone": "America/Chicago",
  "ConnectionType": "Residential"
}
```

Key fields:
- IP: Queried IP address.
- RecentlySeen: Detection count in sensor network (last 60 days).
- RiskScore: One of Low, Medium, High, Extreme.
- MaskedDevices: Masked devices detected.
- Proxy/VPN/TOR: Anonymizer flags.
- DataCenter: Data center IP.
- SearchEngineBot: Known search engine crawler.
- AbnormalTraffic: Anomalous traffic patterns.
- ASN/Organization/ISP: Network operators.
- Geo: City, Region, Country, CountryCode, Timezone.
- ConnectionType: e.g., Residential, Mobile, Corporate, etc.
