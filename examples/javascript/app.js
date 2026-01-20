/**
 * Fraudlogix API Security Implementation - Node.js/Express
 */
const express = require('express');
const axios = require('axios');

const CONFIG = {
  apiKey: process.env.FRAUDLOGIX_API_KEY || 'YOUR_API_KEY_HERE',
  blockedPage: process.env.BLOCKED_PAGE || 'https://yourdomain.com/blocked',
  captchaPage: process.env.CAPTCHA_PAGE || 'https://yourdomain.com/verify',
  scenarios: {
    blockHighExtreme: true,
    quarantineMedium: false,
    strictMode: false,
    blockProxies: true,
    blockAnonymizers: false,
    geoBlocking: true,
  },
  bannedCountries: (process.env.BANNED_COUNTRIES || 'CN,RU').split(','),
};

const app = express();

async function checkIPRisk(ipAddress, apiKey) {
  try {
    const response = await axios.get('https://iplist.fraudlogix.com/v5', {
      headers: { 'x-api-key': apiKey },
      params: { ip: ipAddress },
      timeout: 5000,
    });
    return response.data;
  } catch (err) {
    return null;
  }
}

function fraudlogixSecurity(config = CONFIG) {
  return async (req, res, next) => {
    const visitorIP = (req.headers['x-forwarded-for'] || req.ip || req.connection.remoteAddress || '').toString().split(',')[0].trim();
    const riskData = await checkIPRisk(visitorIP, config.apiKey);
    if (!riskData) return next();

    if (config.scenarios.blockHighExtreme && ['High', 'Extreme'].includes(riskData.RiskScore)) {
      return res.redirect(config.blockedPage);
    }
    if (config.scenarios.quarantineMedium && riskData.RiskScore === 'Medium') {
      return res.redirect(config.captchaPage);
    }
    if (config.scenarios.strictMode && riskData.RiskScore !== 'Low' && !riskData.SearchEngineBot) {
      return res.redirect(config.blockedPage);
    }
    if (config.scenarios.blockProxies && (riskData.Proxy || riskData.VPN || riskData.TOR) && !riskData.SearchEngineBot) {
      return res.redirect(config.blockedPage);
    }
    if (config.scenarios.blockAnonymizers && (riskData.RiskScore === 'Extreme' || riskData.Proxy || riskData.VPN || riskData.TOR)) {
      return res.redirect(config.blockedPage);
    }
    if (config.scenarios.geoBlocking && config.bannedCountries.includes(riskData.CountryCode)) {
      return res.redirect(config.blockedPage);
    }
    next();
  };
}

app.use(fraudlogixSecurity());

app.get('/', (req, res) => {
  res.send('Welcome! You have passed our security checks.');
});

app.get('/blocked', (req, res) => {
  res.status(403).send('Access Denied');
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Server running on port ${port}`));
