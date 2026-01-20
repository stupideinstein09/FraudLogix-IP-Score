/**
 * Fraudlogix API Security Implementation - Java/Spring (sample)
 */
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.http.*;
import org.springframework.web.client.RestTemplate;
import java.util.Arrays;

@Component
public class FraudlogixSecurityInterceptor implements HandlerInterceptor {
    static class Config {
        static String API_KEY = System.getenv("FRAUDLOGIX_API_KEY") != null ? System.getenv("FRAUDLOGIX_API_KEY") : "YOUR_API_KEY_HERE";
        static String BLOCKED_PAGE = System.getenv("BLOCKED_PAGE") != null ? System.getenv("BLOCKED_PAGE") : "https://yourdomain.com/blocked";
        static String CAPTCHA_PAGE = System.getenv("CAPTCHA_PAGE") != null ? System.getenv("CAPTCHA_PAGE") : "https://yourdomain.com/verify";
        static String[] BANNED_COUNTRIES = (System.getenv("BANNED_COUNTRIES") != null ? System.getenv("BANNED_COUNTRIES") : "CN,RU").split(",");
        static boolean BLOCK_HIGH_EXTREME = true;
        static boolean QUARANTINE_MEDIUM = false;
        static boolean STRICT_MODE = false;
        static boolean BLOCK_PROXIES = true;
        static boolean BLOCK_ANONYMIZERS = false;
        static boolean GEO_BLOCKING = true;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        String ip = getClientIP(request);
        RiskData risk = checkIPRisk(ip);
        if (risk == null) return true; // fail-open

        if (Config.BLOCK_HIGH_EXTREME && ("High".equals(risk.RiskScore) || "Extreme".equals(risk.RiskScore))) {
            response.sendRedirect(Config.BLOCKED_PAGE); return false;
        }
        if (Config.QUARANTINE_MEDIUM && "Medium".equals(risk.RiskScore)) {
            response.sendRedirect(Config.CAPTCHA_PAGE); return false;
        }
        if (Config.STRICT_MODE && !"Low".equals(risk.RiskScore) && !risk.SearchEngineBot) {
            response.sendRedirect(Config.BLOCKED_PAGE); return false;
        }
        if (Config.BLOCK_PROXIES && (risk.Proxy || risk.VPN || risk.TOR) && !risk.SearchEngineBot) {
            response.sendRedirect(Config.BLOCKED_PAGE); return false;
        }
        if (Config.BLOCK_ANONYMIZERS && ("Extreme".equals(risk.RiskScore) || risk.Proxy || risk.VPN || risk.TOR)) {
            response.sendRedirect(Config.BLOCKED_PAGE); return false;
        }
        if (Config.GEO_BLOCKING && Arrays.asList(Config.BANNED_COUNTRIES).contains(risk.CountryCode)) {
            response.sendRedirect(Config.BLOCKED_PAGE); return false;
        }
        return true;
    }

    private String getClientIP(HttpServletRequest request) { return request.getRemoteAddr(); }

    static class RiskData {
        public String RiskScore;
        public String CountryCode;
        public boolean Proxy, VPN, TOR, SearchEngineBot;
    }

    private RiskData checkIPRisk(String ip) {
        RestTemplate rt = new RestTemplate();
        HttpHeaders headers = new HttpHeaders(); headers.set("x-api-key", Config.API_KEY);
        HttpEntity<Void> entity = new HttpEntity<>(headers);
        ResponseEntity<RiskData> resp = rt.exchange("https://iplist.fraudlogix.com/v5?ip=" + ip, HttpMethod.GET, entity, RiskData.class);
        return resp.getStatusCode().is2xxSuccessful() ? resp.getBody() : null;
    }
}
