using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Primitives;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;

namespace AuthServer.Web;

// Общее для протокольных эндпоинтов /connect/* (Razor Pages и ConnectController).
public static class ConnectRequest
{
    // Имена кнопок форм consent / подтверждения выхода.
    public const string AcceptField = "submit.Accept";
    public const string DenyField = "submit.Deny";
    public const string LogoutField = "submit.Logout";

    private const string AntiforgeryField = "__RequestVerificationToken";

    public static OpenIddictRequest GetRequiredOpenIddictRequest(this HttpContext context) =>
        context.GetOpenIddictServerRequest()
        ?? throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

    public static IEnumerable<KeyValuePair<string, StringValues>> GetParameters(this HttpRequest request) =>
        request.HasFormContentType ? request.Form : request.Query;

    public static bool HasFormField(this HttpRequest request, string name) =>
        request.HasFormContentType && request.Form.ContainsKey(name);

    // Параметры исходного запроса для повторной отправки формой (consent / подтверждение выхода).
    public static List<KeyValuePair<string, string?>> GetResubmitParameters(this HttpRequest request) =>
        request.GetParameters()
            .Where(p => p.Key is not (AcceptField or DenyField or LogoutField or AntiforgeryField))
            .SelectMany(p => p.Value, (p, v) => KeyValuePair.Create(p.Key, v))
            .ToList();

    public static AuthenticationProperties ErrorProperties(string error, string description) =>
        new(new Dictionary<string, string?>
        {
            [OpenIddictServerAspNetCoreConstants.Properties.Error] = error,
            [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = description
        });
}
