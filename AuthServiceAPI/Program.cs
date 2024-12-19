using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using AuthService.Repositories;

var builder = WebApplication.CreateBuilder(args);

    // Hent miljøvariable
    var token = Environment.GetEnvironmentVariable("VAULT_TOKEN");
    if (string.IsNullOrEmpty(token))
    {
        throw new ApplicationException("VAULT_TOKEN er ikke sat som miljøvariabel.");
    }

    var endPoint = Environment.GetEnvironmentVariable("VaultEndPoint");
    if (string.IsNullOrEmpty(endPoint))
    {
        throw new ApplicationException("VaultEndPoint er ikke sat som miljøvariabel.");
    }

    Console.WriteLine($"VAULT_TOKEN sat til {token}");
    Console.WriteLine($"VaultEndPoint sat til {endPoint}");

    // Hent Secret fra Vault
    var vaultRepository = new VaultRepository(endPoint, token);
    var mySecret = await vaultRepository.GetSecretAsync("Secret");
    if (string.IsNullOrEmpty(mySecret))
    {
        throw new ApplicationException("Secret blev ikke fundet i Vault.");
    }

        var myIssuer = await vaultRepository.GetSecretAsync("Issuer");
    if (string.IsNullOrEmpty(myIssuer))
    {
        throw new ApplicationException("Issuer blev ikke fundet i Vault.");
    }
    Console.WriteLine($"Issuer er: {myIssuer}");
    Console.WriteLine($"Secret er: {mySecret}");

    // Tilføj ConnectionString til konfigurationen
    builder.Configuration.AddInMemoryCollection(new[]
    {
        new KeyValuePair<string, string>("AuthSettings:Secret", mySecret),
        new KeyValuePair<string, string>("AuthSettings:Issuer", myIssuer)
    });

//string mySecret = Environment.GetEnvironmentVariable("Secret") ?? "none";
//string myIssuer = Environment.GetEnvironmentVariable("Issuer") ?? "none";
builder.Services
.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters()
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = myIssuer,
        ValidAudience = "http://userservice:8080",
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(mySecret)),
    };
});

// Add services to the container.
builder.Services.AddHttpClient();
builder.Services.AddControllers();

// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
