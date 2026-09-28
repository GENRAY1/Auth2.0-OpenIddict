using System.Security.Claims;

namespace SampleApi;

public static class ClaimsPrincipalExtensions
{
    public static bool HasScope(this ClaimsPrincipal user, string scope) =>
        user.FindAll("scope").SelectMany(c => c.Value.Split(' ')).Contains(scope);
    
}