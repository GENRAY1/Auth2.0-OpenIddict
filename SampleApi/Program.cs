using Microsoft.AspNetCore.Authentication.JwtBearer;
using SampleApi;

var builder = WebApplication.CreateBuilder(args);
var auth = builder.Configuration.GetSection("Auth");

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(o =>
    {
        o.Authority = auth["Authority"];
        o.Audience = auth["Audience"];
        o.RequireHttpsMetadata = !builder.Environment.IsDevelopment();
        o.MapInboundClaims = false; // оставить sub/scope/role как есть, без SOAP-имён
        o.TokenValidationParameters.NameClaimType = "name";
        o.TokenValidationParameters.RoleClaimType = "role";
    });

builder.Services.AddAuthorizationBuilder()
    .AddPolicy("user", p => p.RequireAssertion(ctx => ctx.User.HasScope("api")))
    .AddPolicy("internal", p => p.RequireAssertion(ctx => ctx.User.HasScope("api")));

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/me", (HttpContext ctx) => ctx.User.Claims.Select(c => new { c.Type, c.Value }))
    .RequireAuthorization("user");

app.MapGet("/internal/ping", (HttpContext ctx) => new { caller = ctx.User.FindFirst("sub")?.Value, ok = true })
    .RequireAuthorization("internal");

app.Run();
