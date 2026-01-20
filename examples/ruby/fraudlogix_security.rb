# Fraudlogix API Security Implementation - Ruby/Rails (sample)
require 'net/http'
require 'json'

class FraudlogixSecurity
  CONFIG = {
    api_key: ENV.fetch('FRAUDLOGIX_API_KEY', 'YOUR_API_KEY_HERE'),
    blocked_page: ENV.fetch('BLOCKED_PAGE', 'https://yourdomain.com/blocked'),
    captcha_page: ENV.fetch('CAPTCHA_PAGE', 'https://yourdomain.com/verify'),
    banned_countries: (ENV.fetch('BANNED_COUNTRIES', 'CN,RU')).split(','),
    scenarios: {
      block_high_extreme: true,
      quarantine_medium: false,
      strict_mode: false,
      block_proxies: true,
      block_anonymizers: false,
      geo_blocking: true
    }
  }

  def self.check_security(request)
    ip = request.remote_ip
    risk = check_ip_risk(ip)
    return true if risk.nil?

    return redirect(CONFIG[:blocked_page]) if CONFIG[:scenarios][:block_high_extreme] && %w[High Extreme].include?(risk['RiskScore'])
    return redirect(CONFIG[:captcha_page]) if CONFIG[:scenarios][:quarantine_medium] && risk['RiskScore'] == 'Medium'
    return redirect(CONFIG[:blocked_page]) if CONFIG[:scenarios][:strict_mode] && risk['RiskScore'] != 'Low' && !risk['SearchEngineBot']
    return redirect(CONFIG[:blocked_page]) if CONFIG[:scenarios][:block_proxies] && (risk['Proxy'] || risk['VPN'] || risk['TOR']) && !risk['SearchEngineBot']
    return redirect(CONFIG[:blocked_page]) if CONFIG[:scenarios][:block_anonymizers] && (risk['RiskScore'] == 'Extreme' || risk['Proxy'] || risk['VPN'] || risk['TOR'])
    return redirect(CONFIG[:blocked_page]) if CONFIG[:scenarios][:geo_blocking] && CONFIG[:banned_countries].include?(risk['CountryCode'])

    true
  end

  def self.redirect(url)
    { redirect: url }
  end

  def self.check_ip_risk(ip)
    uri = URI("https://iplist.fraudlogix.com/v5?ip=#{ip}")
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
    request = Net::HTTP::Get.new(uri)
    request['x-api-key'] = CONFIG[:api_key]
    response = http.request(request)
    return nil unless response.code == '200'
    JSON.parse(response.body)
  rescue
    nil
  end
end

# Rails controller usage:
# before_action :fraudlogix_security
# def fraudlogix_security
#   result = FraudlogixSecurity.check_security(request)
#   redirect_to result[:redirect] if result.is_a?(Hash) && result[:redirect]
# end
