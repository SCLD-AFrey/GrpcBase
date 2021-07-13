using System;
using System.IO;
using System.Net.Http;
using System.Security;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using System.Web;
using Grpc.Core;
using Grpc.Net.Client;
using GrpcBase.Common;
using DidiSoft.OpenSsl;
using DidiSoft.OpenSsl.X509;
using GrpcBase.CLI.Encryption;

namespace GrpcBase.CLI
{
    class Program
    {
        private const string Address = "localhost:5001";
        private static string token;
        
        
        private static EncryptionEngine encryptionEngine = new EncryptionEngine();
        private static string filePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "certData");
        private static SecureString secPass = EncryptionEngine.StringToSecureString(@"P@ssword");
        private static X509Certificate2 ServerCert = new X509Certificate2();
        
        
        static async Task Main(string[] args)
        {
            try
            {
                var cert = encryptionEngine.LoadX509Certificate2FromFile(Path.Combine(filePath, "scld.cert"), secPass);
                var client = CreateClient(cert);
                await Authenticate(cert);

                var input = Console.ReadLine();

                while (input.ToLower() != "exit")
                {
                    var request = new BroadcastRequest()
                    {
                        Content = input
                    };
                    var reply = await ProcessRequest(request, client);
                    Console.WriteLine(reply);
                    input = Console.ReadLine();
                }

            }
            catch (Exception e)
            {
                Console.WriteLine($"ERROR: [{e.Message}]");
            }
        }
        
        private static Task<BroadcastReply> ProcessRequest(BroadcastRequest request, Broadcaster.BroadcasterClient client)
        {
            return client.RespondToRequestAsync(request).ResponseAsync;
        }

        private static Broadcaster.BroadcasterClient CreateClient(X509Certificate2 certificate)
        {
            var handler = new HttpClientHandler();
            handler.ClientCertificates.Add(certificate);
            
            var httpClient = new HttpClient(handler);

            // Create the gRPC channel
            // var channel = GrpcChannel.ForAddress($"https://{Address}", new GrpcChannelOptions
            // {
            //     HttpClient  = httpClient
            // });

            var channel = createAuthenticatedChannel($"https://{Address}", httpClient);

            return new Broadcaster.BroadcasterClient(channel);
        }

        private static GrpcChannel createAuthenticatedChannel(string p_address, HttpClient p_httpClient)
        {
            var credentials = CallCredentials.FromInterceptor((context, metadata) =>
            {
                if (!string.IsNullOrEmpty(token))
                {
                    metadata.Add("Authorization", $"Bearer {token}");
                }
                return Task.CompletedTask;
            });
            var channel = GrpcChannel.ForAddress(p_address, new GrpcChannelOptions
            {
                Credentials = ChannelCredentials.Create(new SslCredentials(), credentials),
                HttpClient = p_httpClient
            });
            return channel;
        }

        private static async Task<string> Authenticate(X509Certificate2 p_certificate2)
        {
            Console.WriteLine($"Authenticating as {Environment.UserName}...");
            var handler = new HttpClientHandler();
            handler.ClientCertificates.Add(p_certificate2);
            var httpClient = new HttpClient(handler);

            var request = new HttpRequestMessage
            {
                RequestUri = new Uri($"https://{Address}/generateJwtToken?name={HttpUtility.UrlEncode(Environment.UserName)}&role=client"),
                Method = HttpMethod.Get,
                Version = new Version(2, 0)
            };
            var tokenResponse = await httpClient.SendAsync(request);
            tokenResponse.EnsureSuccessStatusCode();

            token = await tokenResponse.Content.ReadAsStringAsync();
            Console.WriteLine("Successfully authenticated.");

            return token;
        }
    }
}