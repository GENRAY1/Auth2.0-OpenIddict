using AuthServer.DataAccess;
using AuthServer.Startup.Options;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.Options;
using Npgsql;

namespace AuthServer.Startup;

public static class DatabaseInitializer
{
    private const long AdvisoryLockKey = 0x4155_5448_5352_5652; // "AUTHSRVR"

    public static async Task InitializeDatabaseAsync(this WebApplication webApplication, CancellationToken ct = default)
    {
        var services = webApplication.Services;
        
        await using var scope = services.CreateAsyncScope();
        var sp = scope.ServiceProvider;
        var db = sp.GetRequiredService<DatabaseContext>();
        var options = sp.GetRequiredService<IOptions<AuthOptions>>().Value;
        var logger = sp.GetRequiredService<ILoggerFactory>().CreateLogger(typeof(DatabaseInitializer));
        
        if (options.ApplyMigrationsOnStartup)
            await EnsureDatabaseExistsAsync(db, ct);

        // Advisory lock сессионный — держим одно соединение открытым на всё время работы.
        await db.Database.OpenConnectionAsync(ct);
        try
        {
            await db.Database.ExecuteSqlAsync($"SELECT pg_advisory_lock({AdvisoryLockKey})", ct);
            try
            {
                if (options.ApplyMigrationsOnStartup)
                {
                    logger.LogInformation("Applying database migrations");
                    await db.Database.MigrateAsync(ct);
                }

                await sp.GetRequiredService<OpenIddictSeeder>().SeedAsync(ct);
            }
            finally
            {
                await db.Database.ExecuteSqlAsync($"SELECT pg_advisory_unlock({AdvisoryLockKey})", CancellationToken.None);
            }
        }
        finally
        {
            await db.Database.CloseConnectionAsync();
        }
    }

    private static async Task EnsureDatabaseExistsAsync(DatabaseContext db, CancellationToken ct)
    {
        var creator = db.GetService<IRelationalDatabaseCreator>();
        if (await creator.ExistsAsync(ct))
            return;

        try
        {
            await creator.CreateAsync(ct);
        }
        catch (PostgresException e) when (e.SqlState == PostgresErrorCodes.DuplicateDatabase)
        {
            // Соседняя реплика успела первой.
        }
    }
}
