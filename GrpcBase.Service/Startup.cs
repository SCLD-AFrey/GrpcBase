using System;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using DidiSoft.OpenSsl;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using PublicKey = DidiSoft.OpenSsl.PublicKey;

namespace GrpcBase.Service
{
    public class Startup
    {

        private readonly JwtSecurityTokenHandler JwtTokenHandler = new JwtSecurityTokenHandler();
        private readonly SymmetricSecurityKey SecurityKey = new SymmetricSecurityKey(Guid.NewGuid().ToByteArray());
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddGrpc();
            
            services.AddAuthorization(options =>
            {
                options.AddPolicy(JwtBearerDefaults.AuthenticationScheme, policy =>
                {
                    policy.AddAuthenticationSchemes(JwtBearerDefaults.AuthenticationScheme);
                    policy.RequireClaim(ClaimTypes.Name);
                });
            });
            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(options =>
                {
                    options.TokenValidationParameters =
                        new TokenValidationParameters
                        {
                            ValidateAudience = false,
                            ValidateIssuer = false,
                            ValidateActor = false,
                            ValidateLifetime = true,
                            IssuerSigningKey = SecurityKey
                        };
                });
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            GenerateCerts();
            
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseRouting();
            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapGrpcService<BroadcastService>();

                endpoints.MapGet("/generateJwtToken", context =>
                {
                    return context.Response.WriteAsync(GenerateJwtToken(context.Request.Query["name"]));
                });
            });
        }
        private string GenerateJwtToken(string name)
        {
            if (string.IsNullOrEmpty(name))
            {
                throw new InvalidOperationException("Name is not specified.");
            }

            var claims = new[] { new Claim(ClaimTypes.Name, name) };
            var credentials = new SigningCredentials(SecurityKey, SecurityAlgorithms.HmacSha256);
            var token = new JwtSecurityToken("ExampleServer", "ExampleClients", claims, expires: DateTime.Now.AddSeconds(60), signingCredentials: credentials);
            return JwtTokenHandler.WriteToken(token);
        }

        private void GenerateCerts()
        {
            PrivateKey privateKey;
            PublicKey publicKey;
            
            string filePath = @"C:\Certs\";
            string pubFileName = "key-public.pem";
            string privFileName = "key-private.pem";

            if (!File.Exists(filePath + pubFileName) || !File.Exists(filePath + privFileName))
            {
                KeyPair kp = KeyPair.GenerateKeyPair(KeyAlgorithm.Rsa, KeyLength.Length2048);
                publicKey = kp.Public;
                privateKey = kp.Private;
                
                publicKey.Save(filePath + pubFileName);
                privateKey.Save(filePath + privFileName);
                
                
            }
            else
            {
                publicKey = PublicKey.Load(filePath + pubFileName);
                privateKey = PrivateKey.Load(filePath + privFileName);
            }
        }
    }
}
