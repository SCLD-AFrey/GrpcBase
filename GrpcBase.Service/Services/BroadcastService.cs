using Grpc.Core;
using System;
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
            return Task.FromResult(new BroadcastReply
            {
                Content = $"You ({user.Identity.Name}) wrote {request.Content} at {at.ToDateTime().ToString("h:mm:ss tt")}",
                At = new Timestamp()
            });
        }
    }
}