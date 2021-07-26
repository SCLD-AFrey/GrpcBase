using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using DevExpress.Xpo;
using DevExpress.Xpo.DB;
using GrpcBase.Data;
using Microsoft.IdentityModel.Tokens;

namespace GrpcBase.Service
{
    public static class TokenHandling
    {
        public static bool HasRole(ClaimsPrincipal p_principal, string p_role)
        {   
            return ((ClaimsIdentity) p_principal.Identity).HasClaim(ClaimTypes.Role, p_role);
        }
        public static string GenerateJwtToken(string p_name, JwtSecurityTokenHandler p_jwtTokenHandler, SymmetricSecurityKey p_securityKey)
        {
            if (string.IsNullOrEmpty(p_name))
            {
                throw new InvalidOperationException("Name is not specified.");
            }

            UnitOfWork uow = new UnitOfWork()
            {
                ConnectionString = "XpoProvider=MSSqlServer;data source=(localdb)\\MSSQLLocalDB;integrated security=SSPI;initial catalog=SampleData",
                AutoCreateOption = AutoCreateOption.DatabaseAndSchema
            };
            
            XPCollection<User> users = new XPCollection<User>(uow);
            XPCollection<Role> roles = new XPCollection<Role>(uow);

            if (roles.Count == 0)
            {
                var r1 = new Role(uow) {Name = "Admin"};
                var r2 = new Role(uow) {Name = "Reader"};
                var r3 = new Role(uow) {Name = "Power User"};
                var r4 = new Role(uow) {Name = "User"};
                
                if (users.Count == 0)
                {
                    users.Add(new User(uow) {UserName = "afrey", Roles = {r1, r2}});
                    users.Add(new User(uow) {UserName = "lfrey", Roles = {r3, r4}});
                    users.Add(new User(uow) {UserName = "efrey", Roles = {r3}});
                    users.Add(new User(uow) {UserName = "ffrey", Roles = {r4}});
                }
                
                uow.CommitChanges();
            }
   
            var user = users.FirstOrDefault(x => x.UserName == p_name);

            List<Claim> _claims = new List<Claim>();
            _claims.Add(new Claim(ClaimTypes.Name, p_name));

            foreach (var role in user.Roles)
            {
                _claims.Add(new Claim(ClaimTypes.Role, role.Name));
            }

            

            Claim[] claims = _claims.ToArray();
            
            
            var credentials = new SigningCredentials(p_securityKey, SecurityAlgorithms.HmacSha256);
            var token = new JwtSecurityToken(
                "BroadcastServer", 
                "ExampleClients", 
                claims, 
                expires: DateTime.Now.AddSeconds(60), 
                signingCredentials: credentials);
            return p_jwtTokenHandler.WriteToken(token);
        }


    }
}