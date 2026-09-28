using Microsoft.AspNetCore.Identity;

namespace AuthServer.DataAccess.Entities;

public sealed class User : IdentityUser<Guid>
{
    public string? DisplayName { get; set; }
}

