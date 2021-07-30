using System;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using System.Web;
using Grpc.Core;
using Grpc.Net.Client;
using GrpcBase.Common;

namespace GrpcBase.CLI
{
    internal static class Utilities
    {
        internal static async Task<string> GetBearerToken(X509Certificate2 p_certificate2, string Address)
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
        
        internal static AuthenticatorServiceRpc.AuthenticatorServiceRpcClient CreateAuthenticatorClient(X509Certificate2 p_certificate, string p_address)
        {
            var handler = new HttpClientHandler();
            handler.ClientCertificates.Add(p_certificate);
            var httpClient = new HttpClient(handler);
            var channel = Utilities.CreateUnAuthenticatedChannel(httpClient, p_address);

            return new AuthenticatorServiceRpc.AuthenticatorServiceRpcClient(channel);
        }
        internal static Broadcaster.BroadcasterClient CreateBroadcasterClient(X509Certificate2 p_certificate, string p_bearerToken, string p_address)
        {
            var handler = new HttpClientHandler();
            handler.ClientCertificates.Add(p_certificate);
            var httpClient = new HttpClient(handler);
            var channel = Utilities.CreateAuthenticatedChannel(httpClient, p_bearerToken, p_address);

            return new Broadcaster.BroadcasterClient(channel);
        }
        
        internal static GrpcChannel CreateUnAuthenticatedChannel(HttpClient p_httpClient, string p_address)
        {
            var channel = GrpcChannel.ForAddress($"https://{p_address}", new GrpcChannelOptions
            {
                HttpClient = p_httpClient
            });
            return channel;
        }
        internal static GrpcChannel CreateAuthenticatedChannel(HttpClient p_httpClient, string p_token, string p_address)
        {
            var credentials = CallCredentials.FromInterceptor((p_context, p_metadata) =>
            {
                if (!string.IsNullOrEmpty(p_token))
                {
                    p_metadata.Add("Authorization", $"Bearer {p_token}");
                }
                else
                {
                    throw new Exception("TOKEN IS NULL OR EMPTY");
                }
                return Task.CompletedTask;
            });
            var channel = GrpcChannel.ForAddress($"https://{p_address}", new GrpcChannelOptions
            {
                Credentials = ChannelCredentials.Create(new SslCredentials(), credentials),
                HttpClient = p_httpClient
            });
            return channel;
        }
        
    }
}