using Grpc.Core;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using GrpcBase.Common;

namespace GrpcBase.Service
{
    public class BroadcastService : Broadcaster.BroadcasterBase
    {
        public override Task<BroadcastReply> RespondToRequest(BroadcastRequest request, ServerCallContext context)
        {
            var user = context.GetHttpContext().User;
            
            return Task.FromResult(new BroadcastReply
            {
                Content = $"You wrote {request.Content} at {DateTime.Now.ToString("h:mm:ss tt")}"
            });
        }
        
        
    }
}