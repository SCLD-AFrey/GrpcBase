using System;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Hosting;
using System.IO;
using System.Security;
using System.Security.Cryptography.X509Certificates;
using DidiSoft.OpenSsl;
using GrpcBase.Service.Encryption;
using Microsoft.AspNetCore.Server.Kestrel.Https;

namespace GrpcBase.Service
{
    public class Program
    {
        private static EncryptionEngine encryptionEngine = new EncryptionEngine();
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

        private static void GenerateCertificate()
        {
            if (!Directory.Exists(filePath))
            {
                Directory.CreateDirectory(filePath);
            }
            if (!File.Exists(Path.Combine(filePath, "scld.cert")))
            {
                ServerCert = encryptionEngine.GenerateX509Certificate2FromRsaKeyPair(
                    encryptionEngine.GenerateNewAsymmetricRsaKeyPair(KeyLength.Length1024),
                    "TestCert");
                encryptionEngine.SaveX509Certificate2ToFile(
                    ServerCert, 
                    Path.Combine(filePath, "scld.cert"), secPass);
            }
            else
            {
                ServerCert = encryptionEngine.LoadX509Certificate2FromFile(Path.Combine(filePath, "scld.cert"), secPass);
            }
            Console.WriteLine(Path.Combine(filePath, "scld.cert"));
            
        }
    }
}
