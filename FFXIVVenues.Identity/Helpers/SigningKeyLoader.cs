using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using ScottBrady.IdentityModel.Crypto;
using ScottBrady.IdentityModel.Tokens;

namespace FFXIVVenues.Identity.Helpers;

public class SigningKeyLoader(IConfigurationRoot config)
{
    public const string EdDsaKeyId = "ffxivvenues-ed25519-key";
    public const string RsaKeyId = "ffxivvenues-rsa-key";


    private RsaSecurityKey? _rsaSecurityKey;
    private EdDsaSecurityKey? _edDsaSecurityKey;

    public EdDsaSecurityKey LoadEdDsaPrivateKey()
    {
        if (_edDsaSecurityKey is not null)
            return _edDsaSecurityKey;

        var pemPath = config.GetValue("Signing:Ed25519:PrivateKeyPath", "config/ed25519/private.pem")!;
        var pem = File.ReadAllText(pemPath);
        var d = LoadKey(pem, wantPrivate: true);
        var edDsa = EdDsa.Create(new EdDsaParameters(ExtendedSecurityAlgorithms.Curves.Ed25519) { D = d });
        return _edDsaSecurityKey = new EdDsaSecurityKey(edDsa) { KeyId = EdDsaKeyId };
    }

    public JsonWebKey LoadEdDsaPublicJwk()
    {
        var edDsaPath = config.GetValue<string>("Signing:Ed25519:PublicKeyPath", "config/ed25519/public.pub")!;
        var pem = System.IO.File.ReadAllText(edDsaPath);

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

    public RsaSecurityKey LoadRsaPrivateKey()
    {
        if (_rsaSecurityKey is not null)
            return _rsaSecurityKey;

        var pemPath = config.GetValue("Signing:Rsa:PrivateKeyPath", "config/rsa/private.pem")!;
        var pem = File.ReadAllText(pemPath);
        var rsa = RSA.Create();
        rsa.ImportFromPem(pem);
        return _rsaSecurityKey = new RsaSecurityKey(rsa) { KeyId = RsaKeyId };
    }

    public JsonWebKey LoadRsaPublicJwk()
    {
        var rsaPath = config.GetValue<string>("Signing:Rsa:PublicKeyPath", "config/rsa/public.pub")!;
        var pem = System.IO.File.ReadAllText(rsaPath);

        using var rsa = RSA.Create();
        rsa.ImportFromPem(pem);
        var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(new RsaSecurityKey(rsa));
        jwk.Use = "sig";
        jwk.Alg = SecurityAlgorithms.RsaSha256;
        jwk.Kid = RsaKeyId;
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
