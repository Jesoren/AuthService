namespace AuthService.Models;
using System.Text.Json.Serialization;
public class LoginModel
{
    [JsonPropertyName("username")]
    public string? Username { get; set; }
    
    [JsonPropertyName("password")]
    public string? Password { get; set; }
}