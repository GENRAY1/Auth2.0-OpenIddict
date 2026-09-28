using AuthServer;
using AuthServer.Startup;

var builder = WebApplication.CreateBuilder(args);


builder.Services.AddDatabase(builder.Configuration);
builder.Services.AddScheduling(builder.Configuration);

builder.Services.AddIdentity(builder.Configuration);
builder.Services.AddOpenId(builder.Configuration, builder.Environment);

builder.Services.AddWebUi();

builder.Services.AddCors(o => o.AddDefaultPolicy(p => p
    .AllowAnyOrigin()
    .AllowAnyMethod()
    .AllowAnyHeader())
);

var app = builder.Build();

await app.InitializeDatabaseAsync();

app.UseStaticFiles();
app.UseRouting();
app.UseCors();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();
app.MapRazorPages();

app.Run();
