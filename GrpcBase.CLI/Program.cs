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
                var bearerToken = await Utilities.GetBearerToken(cert, Address);
                var client = Utilities.CreateClient(cert, bearerToken, Address);
                var input = Console.ReadLine();

                while (input.ToLower() != "exit")
                {
                    try
                    {
                        var reply = await ProcessRequest(new BroadcastRequest() {Content = input}, client);
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


    }
}