using System;
using System.Threading.Tasks;
using Grpc.Net.Client;
using GrpcBase.Common;

namespace GrpcBase.CLI
{
    class Program
    {
        static async Task Main(string[] args)
        {
            using var channel = GrpcChannel.ForAddress("https://localhost:5001");
            var client = new Broadcaster.BroadcasterClient(channel);
            
            
            
            var input = System.Console.ReadLine();
            
            
            while (input.ToLower() != "exit")
            {

                var request = new BroadcastRequest()
                {
                    Content = input
                };
                var reply = await ProcessRequest(request, client);
                
                System.Console.WriteLine(reply);

                input = System.Console.ReadLine();
            }
            
            
            
        }
        private static Task<BroadcastReply> ProcessRequest(BroadcastRequest request, Broadcaster.BroadcasterClient client)
        {
            return client.RespondToRequestAsync(request).ResponseAsync;
        }
    }
}