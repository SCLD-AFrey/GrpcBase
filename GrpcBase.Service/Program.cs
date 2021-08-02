using System;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Hosting;
using System.IO;
using System.Security;
using System.Security.Cryptography.X509Certificates;
using DidiSoft.OpenSsl;
using GrpcBase.Common;
using GrpcBase.Common.Encryption;
using Microsoft.AspNetCore.Server.Kestrel.Https;


namespace GrpcBase.Service
{
    public class Program
    {
        private static string filePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "certData");
        private static SecureString secPass = EncryptionEngine.StringToSecureString(@"P@ssword");
        private static X509Certificate2 ServerCert = new X509Certificate2();
        public static void Main(string[] args)
        {
            GenerateCertificate();
            CreateHostBuilder(args).Build().Run();
        }

        // Additional configuration is required to successfully run gRPC on macOS.
        // For instructions on how to configure Kestrel and gRPC clients on macOS, visit https://go.microsoft.com/fwlink/?linkid=2099682
        public static IHostBuilder CreateHostBuilder(string[] args) =>
            Host.CreateDefaultBuilder(args)
                .ConfigureWebHostDefaults(webBuilder =>
                {
                    webBuilder.UseStartup<Startup>().ConfigureKestrel(
                        kestrelServerOptions =>
                        {
                            kestrelServerOptions.ConfigureHttpsDefaults(opt =>
                            {
                                opt.ClientCertificateMode = ClientCertificateMode.RequireCertificate;

                                // Verify that client certificate was issued by same CA as server certificate
                                opt.ClientCertificateValidation = (certificate, chain, errors) =>
                                    certificate.Issuer == ServerCert.Issuer;
                            });
                        });
                });

        private static void CreateCertStore()
        {
            X509Store store = new X509Store("MY",StoreLocation.CurrentUser);
        }
        
        private static void GenerateCertificate()
        {
            if (!Directory.Exists(filePath))
            {
                Directory.CreateDirectory(filePath);
            }
            if (!File.Exists(Path.Combine(filePath, "scld.crt")))
            {
                ServerCert = GrpcBase.Common.Encryption.EncryptionEngine.GenerateX509Certificate2FromRsaKeyPair(
                    EncryptionEngine.GenerateNewAsymmetricRsaKeyPair(
                        KeyLength.Length1024),
                    "TestCert");
                EncryptionEngine.SaveX509Certificate2ToFile(
                    ServerCert, 
                    Path.Combine(filePath, "scld.crt"), secPass);
            } 
            else
            {
                ServerCert = EncryptionEngine.LoadX509Certificate2FromFile(Path.Combine(filePath, "scld.crt"), secPass);
            }
            
            EncryptionEngine.StoreX509Certificate2InX509Store(ServerCert);
            
            
            Console.WriteLine(Path.Combine(filePath, "scld.crt"));
            
        }
    }
}
