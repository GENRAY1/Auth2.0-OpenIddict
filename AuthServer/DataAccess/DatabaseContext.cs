using AuthServer.DataAccess.Entities;
using Microsoft.AspNetCore.DataProtection.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace AuthServer.DataAccess;

public sealed class DatabaseContext(DbContextOptions<DatabaseContext> options)
    : IdentityDbContext<User, Role, Guid>(options), IDataProtectionKeyContext
{
    public DbSet<DataProtectionKey> DataProtectionKeys => Set<DataProtectionKey>();

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        builder.UseOpenIddict();

        builder.Entity<User>()
            .HasIndex(u => u.NormalizedEmail);
    }
}
