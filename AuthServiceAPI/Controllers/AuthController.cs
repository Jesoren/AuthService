using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using AuthService.Models;
using System.Text.Json;

namespace AuthServiceAPI.Controllers;

[ApiController]
[Route("[controller]")]
public class AuthController : ControllerBase
{
    private readonly ILogger<AuthController> _logger;
    private readonly IConfiguration _config;

    private readonly IHttpClientFactory _httpClientFactory;

    public AuthController(ILogger<AuthController> logger, IConfiguration config, IHttpClientFactory httpClientFactory)
    {
        _config = config;
        _logger = logger;
        _httpClientFactory = httpClientFactory;
    }

    private string GenerateJwtToken(string username)
    {
        var securityKey =
        new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["AuthSettings:Secret"]));
        var credentials =
        new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
        var claims = new[]
        {
new Claim(ClaimTypes.NameIdentifier, username)
};
        var token = new JwtSecurityToken(
        _config["AuthSettings:Issuer"],
        "http://localhost",
        claims,
        expires: DateTime.Now.AddMinutes(15),
        signingCredentials: credentials);
        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private async Task<LoginModel?> GetUserData(LoginModel login)
    {
        var endpointUrl = _config["UserServiceEndpoint"]! + login.Username;
        _logger.LogInformation("Retrieving user data from: {}", endpointUrl);

        var client = _httpClientFactory.CreateClient();
        HttpResponseMessage response;

        try
        {
            client.DefaultRequestHeaders.Add("Accept", "application/json");
            response = await client.GetAsync(endpointUrl);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, ex.Message);
            return null;
        }

        if (response.IsSuccessStatusCode)
        {
            try
            {
                string? userJson = await response.Content.ReadAsStringAsync();
                _logger.LogInformation($"Response from userservice: {userJson}");
                return JsonSerializer.Deserialize<LoginModel>(userJson);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, ex.Message);
                return null;
            }
        }

        return null;
    }


    [AllowAnonymous]
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginModel login)
    {
        if (login == null || string.IsNullOrEmpty(login.Username) || string.IsNullOrEmpty(login.Password))
        {
            return BadRequest("Username and password are required.");
        }


        var user = await GetUserData(login);

        if (user == null)
        {
            _logger.LogWarning("Invalid login attempt for user: {Username}", login.Username);
            return Unauthorized("Invalid username or password");
        }

        _logger.LogInformation($"User password from database: {user.Password}");
        _logger.LogInformation($"Login password provided: {login.Password}");

        // Ensure user.Password is not null before comparison
        if (string.IsNullOrEmpty(user.Password) || user.Password != login.Password)
        {
            _logger.LogWarning("Invalid password attempt for user: {Username}", login.Username);
            return Unauthorized("Invalid password");
        }

        try
        {
                    // If credentials are valid, generate JWT token
            var token = GenerateJwtToken(login.Username);
            return Ok(new { token });
        }
        
    catch (Exception ex)
    {
        _logger.LogError(ex, "Failed to generate JWT token for user: {Username}", login.Username);
        return StatusCode(500, "Internal server error.");
    }
    }
}