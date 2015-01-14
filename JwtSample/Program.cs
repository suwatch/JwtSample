using System;
using System.Collections.Generic;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;

namespace JwtSample
{
    class Program
    {
        public const string JwtIssuer = "https://geomaster.azurewebsites.windows.net/";
        public const string JwtAudience = "https://management.core.windows.net/";

        static void Main(string[] args)
        {
            try
            {
                var issuerPfx = new X509Certificate2(@"c:\temp\issuer.pfx", File.ReadAllText(@"c:\temp\issuer.pfx.txt"));

                var claims = new[] { new Claim("name", "suwatch"), new Claim("puid", "12345") };
                var jwt = CreateJwt(claims, issuerPfx);
                Console.WriteLine(jwt);

                // multiple certs to validate for Key rollover scenario
                var issuerCers = new[] 
                {
                    new X509Certificate2(@"c:\temp\other.cer"),
                    new X509Certificate2(@"c:\temp\issuer.cer"),
                };

                var results = ValidateJwt(jwt, issuerCers);
                foreach (var claim in results)
                {
                    Console.WriteLine("{0}: {1}", claim.Type, claim.Value);
                }
            }
            catch(Exception ex)
            {
                Console.WriteLine(ex);
            }
        }

        static string CreateJwt(IEnumerable<Claim> claims, X509Certificate2 issuerPfx)
        {
            var now = DateTime.UtcNow;
            var handler = new JwtSecurityTokenHandler();
            var jwt = handler.CreateToken(
                issuer: JwtIssuer,
                audience: JwtAudience,
                subject: new ClaimsIdentity(claims),
                notBefore: now,
                expires: now.AddMinutes(10),
                signingCredentials: new X509SigningCredentials(issuerPfx),
                signatureProvider: null);

            return jwt.RawData;
        }

        static IEnumerable<Claim> ValidateJwt(string jwt, X509Certificate2[] issuerCers)
        {
            var parameters = new TokenValidationParameters();
            parameters.CertificateValidator = X509CertificateValidator.None;
            parameters.ValidateAudience = true;
            parameters.ValidAudience = JwtAudience;
            parameters.ValidateIssuer = true;
            parameters.ValidIssuer = JwtIssuer;
            parameters.ValidateLifetime = true;
            parameters.ClockSkew = TimeSpan.FromMinutes(5);

            var signingTokens = new List<SecurityToken>();
            signingTokens.AddRange(issuerCers.Select(cert => new X509SecurityToken(cert)));
            parameters.IssuerSigningTokens = signingTokens;

            var handler = new JwtSecurityTokenHandler();
            SecurityToken result = null;
            var principal = handler.ValidateToken(jwt, parameters, out result);
            return principal.Claims;
        }
    }
}
