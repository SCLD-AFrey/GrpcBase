using System;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using System.Web;
using Grpc.Core;
using Grpc.Net.Client;
using GrpcBase.Common;
using DidiSoft.OpenSsl;
using PublicKey = DidiSoft.OpenSsl.PublicKey;

namespace GrpcBase.CLI
{
    class Program
    {
        private const string Address = "localhost:5001";
        private static string _token;
        static async Task Main(string[] args)
        {
            //using var channel = GrpcChannel.ForAddress("https://localhost:5001");
            //var client = new Broadcaster.BroadcasterClient(channel);

            
            var certPem = File.ReadAllText(@"C:\Certs\key-public.pem");
            
            PublicKey publicKey = PublicKey.Load(@"C:\Certs\key-public.pem");
            
            X509Certificate2 cert = new X509Certificate2(certPem);
            
            
            
            
            
            var client = CreateClient(cert);
            

            await Authenticate();
            
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

        private static Broadcaster.BroadcasterClient CreateClient(X509Certificate2 certificate)
        {
            var handler = new HttpClientHandler();
            handler.ClientCertificates.Add(certificate);

            // Create the gRPC channel
            var channel = GrpcChannel.ForAddress("https://localhost:5001", new GrpcChannelOptions
            {
                HttpHandler = handler
            });

            return new Broadcaster.BroadcasterClient(channel);
        }
        
        private static Task<BroadcastReply> ProcessRequest(BroadcastRequest request, Broadcaster.BroadcasterClient client)
        {
            return client.RespondToRequestAsync(request).ResponseAsync;
        }
        
        

        private static GrpcChannel CreateAuthenticatedChannel(string address)
        {
            var credentials = CallCredentials.FromInterceptor((context, metadata) =>
            {
                if (!string.IsNullOrEmpty(_token))
                {
                    metadata.Add("Authorization", $"Bearer {_token}");
                }
                return Task.CompletedTask;
            });

            var channel = GrpcChannel.ForAddress(address, new GrpcChannelOptions
            {
                Credentials = ChannelCredentials.Create(new SslCredentials(), credentials)
            });
            return channel;
        }
        
        

        private static async Task<string> Authenticate()
        {
            Console.WriteLine($"Authenticating as {Environment.UserName}...");
            var httpClient = new HttpClient();
            var request = new HttpRequestMessage
            {
                RequestUri = new Uri($"https://{Address}/generateJwtToken?name={HttpUtility.UrlEncode(Environment.UserName)}"),
                Method = HttpMethod.Get,
                Version = new Version(2, 0)
            };
            var tokenResponse = await httpClient.SendAsync(request);
            tokenResponse.EnsureSuccessStatusCode();

            var token = await tokenResponse.Content.ReadAsStringAsync();
            Console.WriteLine("Successfully authenticated.");

            return token;
        }
    }
}