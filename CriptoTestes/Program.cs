using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

class Program
{
    static void Main()
    {
        // Solicitar informações do usuário
        Console.WriteLine("Enter Country Name (2 letter code):");
        string countryName = Console.ReadLine();

        Console.WriteLine("Enter State or Province Name:");
        string stateOrProvinceName = Console.ReadLine();

        Console.WriteLine("Enter Locality Name (City):");
        string localityName = Console.ReadLine();

        Console.WriteLine("Enter Organization Name:");
        string organizationName = Console.ReadLine();

        Console.WriteLine("Enter Organizational Unit Name:");
        string organizationalUnitName = Console.ReadLine();

        Console.WriteLine("Enter Common Name (e.g., domain name):");
        string commonName = Console.ReadLine();

        Console.WriteLine("Enter Email Address:");
        string emailAddress = Console.ReadLine();

        // Gerar um par de chaves RSA
        using (RSA rsa = RSA.Create(2048))
        {
            // Criar um certificado X509 com informações parametrizadas
            var certificateRequest = new CertificateRequest(
                new X500DistinguishedName($"C={countryName}, ST={stateOrProvinceName}, L={localityName}, O={organizationName}, OU={organizationalUnitName}, CN={commonName}, E={emailAddress}"),
                rsa,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);

            // Criar um certificado autoassinado
            X509Certificate2 rootCertificate = certificateRequest.CreateSelfSigned(
                DateTimeOffset.UtcNow,
                DateTimeOffset.UtcNow.AddYears(10));

            // Exportar o certificado para PEM
            string certPem = ExportCertificateToPem(rootCertificate);
            File.WriteAllText("rootca.pem", certPem);

            // Exportar a chave privada para PEM
            string privateKeyPem = ExportPrivateKeyToPem(rsa);
            File.WriteAllText("private_key.pem", privateKeyPem);

            Console.WriteLine("Certificado e chave privada foram gerados e exportados para PEM.");
        }
    }

    static string ExportCertificateToPem(X509Certificate2 certificate)
    {
        var builder = new StringBuilder();
        builder.AppendLine("-----BEGIN CERTIFICATE-----");
        builder.AppendLine(Convert.ToBase64String(certificate.Export(X509ContentType.Cert), Base64FormattingOptions.InsertLineBreaks));
        builder.AppendLine("-----END CERTIFICATE-----");
        return builder.ToString();
    }

    static string ExportPrivateKeyToPem(RSA rsa)
    {
        var rsaParameters = rsa.ExportParameters(true);
        var rsaKey = new RSACryptoServiceProvider();
        rsaKey.ImportParameters(rsaParameters);

        var privateKey = rsaKey.ExportCspBlob(true);
        var base64 = Convert.ToBase64String(privateKey, Base64FormattingOptions.InsertLineBreaks);

        var builder = new StringBuilder();
        builder.AppendLine("-----BEGIN PRIVATE KEY-----");
        builder.AppendLine(base64);
        builder.AppendLine("-----END PRIVATE KEY-----");

        return builder.ToString();
    }
}

