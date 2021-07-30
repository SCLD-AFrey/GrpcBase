using Grpc.Core;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Threading.Tasks;
using Google.Protobuf.WellKnownTypes;
using GrpcBase.Common;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;

namespace GrpcBase.Service
{
    public class AuthenticateService : AuthenticatorServiceRpc.AuthenticatorServiceRpcBase
    {
        private readonly JwtSecurityTokenHandler m_jwtTokenHandler = new JwtSecurityTokenHandler();
        private readonly SymmetricSecurityKey m_securityKey = new SymmetricSecurityKey(Guid.NewGuid().ToByteArray());
        private TokenHandler m_tokenHandler;
        public override Task<AuthReply> AuthenticateUser(AuthRequest p_request, ServerCallContext p_context)
        {
            var user = p_context.GetHttpContext().User;
            return Task.FromResult(new AuthReply()
                {Token = TokenHandling.GenerateJwtToken(p_request.Username, m_jwtTokenHandler, m_securityKey)});

        }
        
        
    }
}