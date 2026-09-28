namespace AuthServer.OpenId.Oidc.Types;

public sealed record OidcLoginResult(OidcLoginStatus Status, string? Error = null);

public enum OidcLoginStatus
{
    SignedIn,
    Linked,
    LockedOut,
    EmailConflict,
    LinkedToAnotherUser,
    Failed
}