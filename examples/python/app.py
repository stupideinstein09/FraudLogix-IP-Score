"""
Fraudlogix API Security Implementation - All 6 Scenarios (Python/Flask)
"""

import os
import requests
from functools import wraps
from flask import Flask, request, redirect

CONFIG = {
    'api_key': os.getenv('FRAUDLOGIX_API_KEY', 'YOUR_API_KEY_HERE'),
    'blocked_page': os.getenv('BLOCKED_PAGE', 'https://yourdomain.com/blocked'),
    'captcha_page': os.getenv('CAPTCHA_PAGE', 'https://yourdomain.com/verify'),
    'scenarios': {
        'block_high_extreme': True,
        'quarantine_medium': False,
        'strict_mode': False,
        'block_proxies': True,
        'block_anonymizers': False,
        'geo_blocking': True,
    },
    'banned_countries': ['CN', 'RU'],
}

app = Flask(__name__)


def fraudlogix_security_check(config=CONFIG):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            visitor_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
            risk_data = check_ip_risk(visitor_ip, config['api_key'])
            if not risk_data:
                return f(*args, **kwargs)  # fail-open

            # 1
            if config['scenarios']['block_high_extreme'] and risk_data.get('RiskScore') in ['High', 'Extreme']:
                return redirect(config['blocked_page'])

            # 2
            if config['scenarios']['quarantine_medium'] and risk_data.get('RiskScore') == 'Medium':
                return redirect(config['captcha_page'])

            # 3
            if config['scenarios']['strict_mode'] and risk_data.get('RiskScore') != 'Low' and not risk_data.get('SearchEngineBot'):
                return redirect(config['blocked_page'])

            # 4
            if config['scenarios']['block_proxies'] and (risk_data.get('Proxy') or risk_data.get('VPN') or risk_data.get('TOR')) and not risk_data.get('SearchEngineBot'):
                return redirect(config['blocked_page'])

            # 5
            if config['scenarios']['block_anonymizers'] and (risk_data.get('RiskScore') == 'Extreme' or risk_data.get('Proxy') or risk_data.get('VPN') or risk_data.get('TOR')):
                return redirect(config['blocked_page'])

            # 6
            if config['scenarios']['geo_blocking'] and risk_data.get('CountryCode') in config['banned_countries']:
                return redirect(config['blocked_page'])

            return f(*args, **kwargs)
        return decorated
    return decorator


def check_ip_risk(ip, api_key):
    try:
        headers = {'x-api-key': api_key}
        resp = requests.get('https://iplist.fraudlogix.com/v5', headers=headers, params={'ip': ip}, timeout=5)
        return resp.json() if resp.status_code == 200 else None
    except Exception:
        return None


@app.route('/')
@fraudlogix_security_check()
def home():
    return 'Welcome! You have passed our security checks.'


@app.route('/blocked')
def blocked():
    return 'Access Denied', 403


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
