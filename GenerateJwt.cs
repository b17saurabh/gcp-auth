using System.Security.Cryptography;
using System.Text;
using JWT;
using Newtonsoft.Json;

namespace gcp_auth;
public static class AccessToken
{
    public static async Task<string> GetAccessTokenAsync(string privateKey, string privatekeyId, string serviceAccountEmail, string scope)
    {
        try
        {
            string jwt = GenerateJwt( privateKey, privatekeyId, serviceAccountEmail, scope);
            return await ExchangeTokenAsync(jwt);
        }
        catch (Exception ex)
        {
            throw ex;
        }

    }
    public static string GenerateJwt(string privateKey, string privatekeyId, string serviceAccountEmail, string scope)
    {
        int issued = (int)(DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds;
        int expires = issued + 3600;

        var header = GetHeaders(privatekeyId);

        var payload = GetPayload(serviceAccountEmail, scope, issued, expires);

        var privateKeybyteArray = ReadPrivateKey(privateKey);

        var jwt = EncodeRSA(header, payload, privateKeybyteArray);
        return jwt;

    }

    private static Dictionary<string, object> GetPayload(string serviceAccountEmail, string scope, int issued, int expires)
    {
        return new Dictionary<string, object>
                {
                    {"iss", serviceAccountEmail},
                    {"sub", serviceAccountEmail},
                    {"aud", "https://www.googleapis.com/oauth2/v4/token"},
                    {"iat", issued},
                    {"exp", expires},
                    {"scope", scope}
            
                };
    }
    

    private static Dictionary<string, object> GetHeaders(string privatekeyId)
    {
        return new Dictionary<string, object>
                {
                    {"alg", "RS256"},
            {"kid", privatekeyId},
            {"typ", "JWT"}
                };
    }

    private static byte[] ReadPrivateKey(string pkey)
    {
        var privateKey = pkey.Replace("-----BEGIN PRIVATE KEY-----", "");
        privateKey = privateKey.Replace("-----END PRIVATE KEY-----", "");
        privateKey = privateKey.Replace("\n", "");
        return Convert.FromBase64String(privateKey);
    }

    private static string EncodeRSA(Dictionary<string, object> extraHeaders, object payload, byte[] key)
    {
        var header = new Dictionary<string, object>
        {
        };

        if (extraHeaders != null)
        {
            foreach (var extraHeader in extraHeaders)
            {
                header.Add(extraHeader.Key, extraHeader.Value);
            }
        }
        var jwtEncoder = new JwtBase64UrlEncoder();
        var segments = new List<string>
        {
            jwtEncoder.Encode(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(header)) ),
            jwtEncoder.Encode(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(payload)))
        };

        var stringToSign = string.Join(".", segments.ToArray());
        var bytesToSign = Encoding.UTF8.GetBytes(stringToSign);

        //sign token with private key rs256
        var rsa = RSA.Create();
        rsa.ImportPkcs8PrivateKey(key, out _);
        var signature = rsa.SignData(bytesToSign, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        segments.Add(jwtEncoder.Encode(signature));

        return string.Join(".", segments.ToArray());
    }


    public static async Task<string> ExchangeTokenAsync(string jwt)
    {
        string authUrl = "https://www.googleapis.com/oauth2/v4/token";
        var client = new System.Net.Http.HttpClient();
        var content = new StringContent(JsonConvert.SerializeObject(
            new
            {
                grant_type = "urn:ietf:params:oauth:grant-type:jwt-bearer",
                assertion = jwt
            }
            ),
           Encoding.UTF8, "application/json");


        var response = await client.PostAsync(authUrl, content);
        var responseContent = response.Content.ReadAsStringAsync().Result;
        var responseJson = JsonConvert.DeserializeObject<Dictionary<string, string>>(responseContent);
        return responseJson["access_token"];
    }
}
