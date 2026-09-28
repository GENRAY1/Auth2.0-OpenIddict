using Microsoft.AspNetCore.Identity;

namespace AuthServer.DataAccess.Entities;

public sealed class Role : IdentityRole<Guid>
{
    public Role() { }

    public Role(string name) : base(name) { }
}