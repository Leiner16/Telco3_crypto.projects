using System;
using System.IO;
using System.Security.Cryptography;

namespace CryptoUtility
{
    class CryptoManager
    {
        static void Main()
        {
            var keyManager = new KeyManager();
            var signatureProcessor = new SignatureProcessor(keyManager);

            Console.WriteLine("Crypto Manager");
            while (true)
            {
                Console.WriteLine("\nSelecciona una opción:");
                Console.WriteLine("1. Generar par de claves");
                Console.WriteLine("2. Firmar mensaje");
                Console.WriteLine("3. Verificar firma");
                Console.WriteLine("4. Salir");

                switch (Console.ReadLine())
                {
                    case "1":
                        keyManager.GenerateKeyPair();
                        break;
                    case "2":
                        signatureProcessor.SignMessage();
                        break;
                    case "3":
                        signatureProcessor.VerifySignature();
                        break;
                    case "4":
                        return;
                    default:
                        Console.WriteLine("Opción no válida.");
                        break;
                }
            }
        }
    }

    class KeyManager
    {
        private readonly string keysPath = "KEYS";

        public KeyManager()
        {
            Directory.CreateDirectory(keysPath);
        }

        public void GenerateKeyPair()
        {
            using (var rsa = new RSACryptoServiceProvider())
            {
                var privateKey = rsa.ExportParameters(true);
                var publicKey = rsa.ExportParameters(false);

                var keyFolder = Path.Combine(keysPath, Guid.NewGuid().ToString());
                Directory.CreateDirectory(keyFolder);

                File.WriteAllText(Path.Combine(keyFolder, "publicKey.xml"), privateKey.ToXmlString());
                File.WriteAllText(Path.Combine(keyFolder, "privateKey.xml"), publicKey.ToXmlString());

                Console.WriteLine($"Claves generadas y guardadas en: {keyFolder}");
            }
        }
    }

    class SignatureProcessor
    {
        private readonly KeyManager keyManager;

        public SignatureProcessor(KeyManager keyManager)
        {
            this.keyManager = keyManager;
        }

        public void SignMessage()
        {
            Console.WriteLine("Ingrese el mensaje a firmar:");
            var message = Console.ReadLine();
            File.WriteAllText("message.txt", message);

            Console.WriteLine("Ingrese la ruta de la clave privada:");
            var privateKeyPath = Console.ReadLine();

            try
            {
                var rsa = new RSACryptoServiceProvider();
                var privateKeyXml = File.ReadAllText(privateKeyPath);
                rsa.FromXmlString(privateKeyXml);

                var messageBytes = System.Text.Encoding.UTF8.GetBytes(message);
                var signature = rsa.SignData(messageBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                File.WriteAllBytes("signature.txt", signature);
                Console.WriteLine("Mensaje firmado. Firma guardada en 'signature.txt'");
            }
            catch (Exception e)
            {
                Console.WriteLine($"Error: {e.Message}");
            }
        }

        public void VerifySignature()
        {
            var message = File.ReadAllText("message.txt");
            Console.WriteLine($"Mensaje a verificar: {message}");

            Console.WriteLine("Ingrese la ruta de la clave pública:");
            var publicKeyPath = Console.ReadLine();

            try
            {
                var rsa = new RSACryptoServiceProvider();
                var publicKeyXml = File.ReadAllText(publicKeyPath);
                rsa.FromXmlString(publicKeyXml);

                var messageBytes = System.Text.Encoding.UTF8.GetBytes(message);
                var signature = File.ReadAllBytes("signature.txt");
                var verified = rsa.VerifyData(messageBytes, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                if (verified)
                    Console.WriteLine("La firma es válida.");
                else
                    Console.WriteLine("La firma es inválida.");
            }
            catch (Exception e)
            {
                Console.WriteLine($"Error: {e.Message}");
            }
        }
    }

    public static class RSAParametersExtensions
    {
        public static string ToXmlString(this RSAParameters parameters)
        {
            using (var sw = new StringWriter())
            {
                var serializer = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
                serializer.Serialize(sw, parameters);
                return sw.ToString();
            }
        }
    }
}
