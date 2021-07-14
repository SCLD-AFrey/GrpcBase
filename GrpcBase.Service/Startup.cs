using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;

namespace GrpcBase.Service
{
    public class Startup
    {
        private readonly JwtSecurityTokenHandler m_jwtTokenHandler = new JwtSecurityTokenHandler();
        private readonly SymmetricSecurityKey m_securityKey = new SymmetricSecurityKey(Guid.NewGuid().ToByteArray());
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddGrpc();

            services.AddAuthorization(configure: options =>
            {
                options.AddPolicy(name: JwtBearerDefaults.AuthenticationScheme, configurePolicy: policy =>
                {
                    policy.AddAuthenticationSchemes(JwtBearerDefaults.AuthenticationScheme);
                    policy.RequireClaim(claimType: ClaimTypes.Name);
                });
            });
            services.AddAuthentication(defaultScheme: JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(configureOptions: options =>
                {
                    options.TokenValidationParameters =
                        new TokenValidationParameters
                        {
                            ValidateAudience = false,
                            ValidateIssuer = false,
                            ValidateActor = false,
                            ValidateLifetime = true,
                            IssuerSigningKey = m_securityKey
                        };
                });
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
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
                    return context.Response.WriteAsync(
                        GenerateJwtToken(
                            context.Request.Query["name"]
                            )
                        );
                });
            });
        }
        private string GenerateJwtToken(string p_name)
        {
            if (string.IsNullOrEmpty(p_name))
            {
                throw new InvalidOperationException("Name is not specified.");
            }

            var claims = new[]
            {
                new Claim(ClaimTypes.Name, p_name)
            };
            
            var credentials = new SigningCredentials(m_securityKey, SecurityAlgorithms.HmacSha256);
            var token = new JwtSecurityToken(
                "BroadcastServer", 
                "ExampleClients", 
                claims, 
                expires: DateTime.Now.AddSeconds(60), 
                signingCredentials: credentials);
            return m_jwtTokenHandler.WriteToken(token);
        }

    }
}
