// Fraudlogix API Security Implementation - C#/.NET Middleware (sample)
using Microsoft.AspNetCore.Http;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;

public static class FraudlogixConfig
{
    public static string ApiKey => Environment.GetEnvironmentVariable("FRAUDLOGIX_API_KEY") ?? "YOUR_API_KEY_HERE";
    public static string BlockedPage => Environment.GetEnvironmentVariable("BLOCKED_PAGE") ?? "https://yourdomain.com/blocked";
    public static string CaptchaPage => Environment.GetEnvironmentVariable("CAPTCHA_PAGE") ?? "https://yourdomain.com/verify";
    public static string[] BannedCountries => (Environment.GetEnvironmentVariable("BANNED_COUNTRIES") ?? "CN,RU").Split(',');
    public static class Scenarios
    {
        public static bool BlockHighExtreme = true;
        public static bool QuarantineMedium = false;
        public static bool StrictMode = false;
        public static bool BlockProxies = true;
        public static bool BlockAnonymizers = false;
        public static bool GeoBlocking = true;
    }
}

public class FraudlogixSecurityMiddleware
{
    private readonly RequestDelegate _next;
    private readonly HttpClient _http;
    public FraudlogixSecurityMiddleware(RequestDelegate next, HttpClient httpClient) { _next = next; _http = httpClient; }

    public async Task InvokeAsync(HttpContext context)
    {
        var ip = context.Connection.RemoteIpAddress?.ToString();
        var risk = await CheckIPRisk(ip);
        if (risk != null)
        {
            if (FraudlogixConfig.Scenarios.BlockHighExtreme && (risk.RiskScore == "High" || risk.RiskScore == "Extreme")) { context.Response.Redirect(FraudlogixConfig.BlockedPage); return; }
            if (FraudlogixConfig.Scenarios.QuarantineMedium && risk.RiskScore == "Medium") { context.Response.Redirect(FraudlogixConfig.CaptchaPage); return; }
            if (FraudlogixConfig.Scenarios.StrictMode && risk.RiskScore != "Low" && !risk.SearchEngineBot) { context.Response.Redirect(FraudlogixConfig.BlockedPage); return; }
            if (FraudlogixConfig.Scenarios.BlockProxies && (risk.Proxy || risk.VPN || risk.TOR) && !risk.SearchEngineBot) { context.Response.Redirect(FraudlogixConfig.BlockedPage); return; }
            if (FraudlogixConfig.Scenarios.BlockAnonymizers && (risk.RiskScore == "Extreme" || risk.Proxy || risk.VPN || risk.TOR)) { context.Response.Redirect(FraudlogixConfig.BlockedPage); return; }
            if (FraudlogixConfig.Scenarios.GeoBlocking && Array.Exists(FraudlogixConfig.BannedCountries, c => c == risk.CountryCode)) { context.Response.Redirect(FraudlogixConfig.BlockedPage); return; }
        }
        await _next(context);
    }

    private async Task<RiskData> CheckIPRisk(string ip)
    {
        try
        {
            _http.DefaultRequestHeaders.Clear();
            _http.DefaultRequestHeaders.Add("x-api-key", FraudlogixConfig.ApiKey);
            var resp = await _http.GetAsync($"https://iplist.fraudlogix.com/v5?ip={ip}");
            if (!resp.IsSuccessStatusCode) return null;
            var json = await resp.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<RiskData>(json, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        }
        catch { return null; }
    }

    public class RiskData
    {
        public string RiskScore { get; set; }
        public string CountryCode { get; set; }
        public bool Proxy { get; set; }
        public bool VPN { get; set; }
        public bool TOR { get; set; }
        public bool SearchEngineBot { get; set; }
    }
}

// Usage in Program.cs:
// var builder = WebApplication.CreateBuilder(args);
// builder.Services.AddHttpClient();
// var app = builder.Build();
// app.UseMiddleware<FraudlogixSecurityMiddleware>();
// app.MapGet("/", () => "Welcome! You have passed our security checks.");
// app.Run();
