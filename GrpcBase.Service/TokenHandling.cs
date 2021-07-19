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
        public static string GenerateJwtToken(string p_name, JwtSecurityTokenHandler p_jwtTokenHandler, SymmetricSecurityKey p_securityKey)
        {
            if (string.IsNullOrEmpty(p_name))
            {
                throw new InvalidOperationException("Name is not specified.");
            }

            UnitOfWork uow = new UnitOfWork()
            {
                ConnectionString =
                    "XpoProvider=MSSqlServer;data source=(localdb)\\MSSQLLocalDB;integrated security=SSPI;initial catalog=SampleData",
                AutoCreateOption = AutoCreateOption.DatabaseAndSchema
            };
            
            XPCollection<User> users = new XPCollection<User>(uow);
            XPCollection<Role> roles = new XPCollection<Role>(uow);

            var user = users.FirstOrDefault(x => x.UserName.ToLower() == p_name.ToLower());

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

        private static ObservableCollection<Role> GetRoles(string UserName)
        {
            ObservableCollection<Role> roles = new ObservableCollection<Role>();


            return roles;

        }
    }
}