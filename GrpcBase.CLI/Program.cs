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
        private static string _token;
        
        
        private static EncryptionEngine _encryptionEngine = new EncryptionEngine();
        private static string _filePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "certData");
        private static SecureString _secPass = EncryptionEngine.StringToSecureString(@"P@ssword");
        private static X509Certificate2 _serverCert = new X509Certificate2();
        
        
        static async Task Main(string[] p_args)
        {
            try
            {
                var cert = _encryptionEngine.LoadX509Certificate2FromFile(Path.Combine(_filePath, "scld.cert"), _secPass);

                _token = await Authenticate(cert);
                var client = CreateClient(cert);

                var input = Console.ReadLine();

                while (input.ToLower() != "exit")
                {
                    var request = new BroadcastRequest()
                    {
                        Content = input
                    };
                    try
                    {
                        var reply = await ProcessRequest(request, client);
                        Console.WriteLine(reply);
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine($"ERROR (ProcessRequest): [{e.Message}]");
                    }
                    input = Console.ReadLine();
                }

            }
            catch (Exception e)
            {
                Console.WriteLine($"ERROR: [{e.Message}]");
            }
        }
        

        private static Task<BroadcastReply> ProcessRequest(BroadcastRequest p_request, Broadcaster.BroadcasterClient p_client)
        {
            return p_client.RespondToRequestAsync(p_request).ResponseAsync;
        }

        private static Broadcaster.BroadcasterClient CreateClient(X509Certificate2 p_certificate)
        {
            var handler = new HttpClientHandler();
            handler.ClientCertificates.Add(p_certificate);
            var httpClient = new HttpClient(handler);
            var channel = CreateAuthenticatedChannel(httpClient);

            return new Broadcaster.BroadcasterClient(channel);
        }

        private static GrpcChannel CreateAuthenticatedChannel(HttpClient p_httpClient)
        {
            var credentials = CallCredentials.FromInterceptor((p_context, p_metadata) =>
            {
                if (!string.IsNullOrEmpty(_token))
                {
                    p_metadata.Add("Authorization", $"Bearer {_token}");
                }
                else
                {
                    throw new Exception("TOKEN IS NULL OR EMPTY");
                }
                return Task.CompletedTask;
            });
            var channel = GrpcChannel.ForAddress($"https://{Address}", new GrpcChannelOptions
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
            
            using var client = new HttpClient(handler);
 
            var tokenResponse = await client.SendAsync(new HttpRequestMessage
            {
                RequestUri = new Uri($"https://{Address}/generateJwtToken?name={HttpUtility.UrlEncode(Environment.UserName)}"),
                Method = HttpMethod.Get,
                Version = new Version(2, 0),
            });
            tokenResponse.EnsureSuccessStatusCode();
            
            Console.WriteLine("Successfully authenticated.");

            return await tokenResponse.Content.ReadAsStringAsync();;
        }
    }
}