using System;
using System.IO;
using System.Security.Cryptography;

class Program
{
    static void Main()
    {
        try
        {
            // Crear una instancia de la clase RSACryptoServiceProvider
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                // Generar el par de claves pública y privada
                RSAParameters privateKey = rsa.ExportParameters(true);
                RSAParameters publicKey = rsa.ExportParameters(false);


                // Guardar la clave pública en un archivo.
                File.WriteAllText("publicKey.txt", ToXmlString(publicKey));

                // Firmar el archivo de texto
                string mensaje = "Hola, mundo!";
                byte[] mensajeBytes = System.Text.Encoding.UTF8.GetBytes(mensaje);
                byte[] firma = rsa.SignData(mensajeBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                // Guardar la firma en un archivo
                File.WriteAllBytes("firma.txt", firma);

                // Verificar la firma
                bool verificado = rsa.VerifyData(mensajeBytes, firma, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                if (verificado)
                {
                    Console.WriteLine("La firma es válida.");
                }
                else
                {
                    Console.WriteLine("La firma es inválida.");
                }
            }



        }
        catch (CryptographicException e)
        {
            Console.WriteLine($"Error de criptografía: {e.Message}");
        }
    }

    // Tip Método para convertir los parámetros RSA a XML
    static string ToXmlString(RSAParameters rsaParameters)
    {
        using (var sw = new System.IO.StringWriter())
        {
            var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
            xs.Serialize(sw, rsaParameters);
            return sw.ToString();
        }
    }
}