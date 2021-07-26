using Grpc.Core;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Claims;
using System.Threading.Tasks;
using Google.Protobuf.WellKnownTypes;
using GrpcBase.Common;
using Microsoft.AspNetCore.Authorization;

namespace GrpcBase.Service
{
    public class BroadcastService : Broadcaster.BroadcasterBase
    {
        [Authorize]
        public override Task<BroadcastReply> RespondToRequest(BroadcastRequest request, ServerCallContext context)
        {
            var user = context.GetHttpContext().User;
            var at = new Timestamp();

            if (TokenHandling.HasRole(user, "Admin"))
            {
                return Task.FromResult(new BroadcastReply
                {
                    Content = $"You {user.Identity.Name} wrote {request.Content} at {at.ToDateTime().ToString("h:mm:ss tt")}",
                    At = new Timestamp()
                });
            }
            else
            {
                return Task.FromResult(new BroadcastReply
                {
                    Content = $"You {user.Identity.Name} do not has permission to do this",
                    At = new Timestamp()
                });
            }
            
        }
    }
}