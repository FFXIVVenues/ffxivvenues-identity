using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using ScottBrady.IdentityModel.Crypto;
using ScottBrady.IdentityModel.Tokens;

namespace FFXIVVenues.Identity.Helpers;

public class SigningKeyLoader
{
    public const string KeyId = "ffxivvenues-signing-key";

    public EdDsaSecurityKey LoadPrivateKey(string pem)
    {
        var d = LoadKey(pem, wantPrivate: true);
        var edDsa = EdDsa.Create(new EdDsaParameters(ExtendedSecurityAlgorithms.Curves.Ed25519) { D = d });
        return new EdDsaSecurityKey(edDsa) { KeyId = KeyId };
    }

    public JsonWebKey LoadPublicJwk(string pem)
    {
        var x = LoadKey(pem, wantPrivate: false);
        return new JsonWebKey
        {
            Kty = "OKP",
            Crv = ExtendedSecurityAlgorithms.Curves.Ed25519,
            X = Base64UrlEncoder.Encode(x),
            Use = "sig",
            Alg = ExtendedSecurityAlgorithms.EdDsa,
            Kid = KeyId
        };
    }

    private byte[] LoadKey(string pem, bool wantPrivate)
    {
        using var reader = new StringReader(pem);
        var pemObject = new PemReader(reader).ReadObject()
            ?? throw new InvalidOperationException("Signing key PEM could not be parsed.");

        var keyParameter = pemObject switch
        {
            AsymmetricCipherKeyPair pair => wantPrivate ? pair.Private : pair.Public,
            AsymmetricKeyParameter parameter => parameter,
            _ => throw new InvalidOperationException($"Unexpected PEM contents: {pemObject.GetType().Name}.")
        };

        return keyParameter switch
        {
            Ed25519PrivateKeyParameters priv when wantPrivate => priv.GetEncoded(),
            Ed25519PublicKeyParameters pub when !wantPrivate => pub.GetEncoded(),
            _ => throw new InvalidOperationException(
                $"Expected an Ed25519 {(wantPrivate ? "private" : "public")} key but got {keyParameter.GetType().Name}.")
        };
    }
}
