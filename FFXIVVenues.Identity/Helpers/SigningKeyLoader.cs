using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using ScottBrady.IdentityModel.Crypto;
using ScottBrady.IdentityModel.Tokens;

namespace FFXIVVenues.Identity.Helpers;

public class SigningKeyLoader
{
    public const string EdDsaKeyId = "ffxivvenues-ed25519-key";
    public const string RsaKeyId = "ffxivvenues-rsa-key";

    public EdDsaSecurityKey LoadEdDsaPrivateKey(string pem)
    {
        var d = LoadKey(pem, wantPrivate: true);
        var edDsa = EdDsa.Create(new EdDsaParameters(ExtendedSecurityAlgorithms.Curves.Ed25519) { D = d });
        return new EdDsaSecurityKey(edDsa) { KeyId = EdDsaKeyId };
    }

    public JsonWebKey LoadEdDsaPublicJwk(string pem)
    {
        var x = LoadKey(pem, wantPrivate: false);
        return new JsonWebKey
        {
            Kty = "OKP",
            Crv = ExtendedSecurityAlgorithms.Curves.Ed25519,
            X = Base64UrlEncoder.Encode(x),
            Use = "sig",
            Alg = ExtendedSecurityAlgorithms.EdDsa,
            Kid = EdDsaKeyId
        };
    }

    public RsaSecurityKey LoadRsaPrivateKey(string pem)
    {
        var rsa = RSA.Create();
        rsa.ImportFromPem(pem);
        return new RsaSecurityKey(rsa) { KeyId = RsaKeyId };
    }

    public JsonWebKey LoadRsaPublicJwk(string pem)
    {
        var rsa = RSA.Create();
        rsa.ImportFromPem(pem);
        var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(new RsaSecurityKey(rsa));
        jwk.Use = "sig";
        jwk.Alg = SecurityAlgorithms.RsaSha256;
        jwk.Kid = RsaKeyId;
        jwk.KeyId = RsaKeyId;
        return jwk;
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
