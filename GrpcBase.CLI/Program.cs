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
        private static EncryptionEngine _encryptionEngine = new EncryptionEngine();
        
        static async Task Main(string[] p_args)
        {
            try
            {
                var cert = _encryptionEngine.LoadX509Certificate2FromFile(Path.Combine(
                        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "certData"), 
                        "scld.crt"), 
                    EncryptionEngine.StringToSecureString(@"P@ssword"));

                Console.WriteLine("Authenticating...");

                var authenticateClient = Utilities.CreateAuthenticatorClient(cert, Address);
                var authReply = await ProcessAuthentication(new AuthRequest(){Username = Environment.UserName}, authenticateClient);
                var bearerToken = authReply.Token;
                
                Console.WriteLine($"Authenticated as {authReply.Token}");
                
                //var bearerToken = await Utilities.GetBearerToken(cert, Address);
                var broadcasterClient = Utilities.CreateBroadcasterClient(cert, bearerToken, Address);
                
                var input = Console.ReadLine();

                while (input.ToLower() != "exit")
                {
                    try
                    {
                        var reply = await ProcessRequest(new BroadcastRequest() {Content = input}, broadcasterClient);
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

        private static Task<AuthReply> ProcessAuthentication(AuthRequest p_request, AuthenticatorServiceRpc.AuthenticatorServiceRpcClient p_client)
        {
            return p_client.AuthenticateUserAsync(p_request).ResponseAsync;
        }




    }
}