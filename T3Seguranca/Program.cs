using System;
using System.Collections;
using System.ComponentModel;
using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using static System.Net.Mime.MediaTypeNames;
using System.Text.RegularExpressions;

namespace T3Seguranca {
    public class Program {
          public static void Main(string[] args)
        {
            // Gerar um novo número primo para ser usado no programa
            //BigInteger a = GeneratePrime(30); // número primo de 30 dígitos
            //Console.WriteLine("Valor primo gerado: " + a.ToString());

            // Valor gerado: 302169981172443897262726089341
            BigInteger a = BigInteger.Parse("302169981172443897262726089341");
            Console.WriteLine("Valor primo gerado: " + a.ToString());

            // Valores de p e g passados pelo desafio (tive que colocar um zero para não dar valor de ponto negativo)
            String p = "0B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371";
            String g = "0A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5";
            
            Console.WriteLine("\nValor de P que é o módulo: " + p.ToString());
            Console.WriteLine("\nValor de G que é a base: " + g.ToString());

            // Cálculo do valor de A para enviar ao professor (g^a mod p)
            BigInteger A = CalculateModulus(g, a, p);
            Console.WriteLine("\nValor de A gerado por (g^a mod p): " + A.ToString());
            Console.WriteLine("\nA Em Hexadecimal para o professor: " + ConvertToHex(A).Substring(1));

            // Valores recebidos pelo professor
            String b = "6C7204F6E00ACEC265BF290F04B636A042A42A4274B066EFC8D50E72A957792BF49FD43A71B426C7CF7B6F5D144ECDF28F917154DF0BABEA437011BE4BD8FB62F940AB576140CD5675F93435CA5A8BCF1B38FE7B3942E8A8D8B9B6155727C60E034F26537BD3DE31BDE997D369032C3DD115ACB03A896C945B399A44F5517D8B";
            String msg = "508FAF6C53475545EC640D73F077839397A214E6E16754814FB6E70185A2BB01B47F893F36FA76F9343E7B005230FEB46ADC668C2719B9A0B1AB6E5BCD20F0AB23108901BD4A023DF938A5274F867538337EF9A7FB1C77087B354548088B42FE6ED770902203D0B7A4BF3F7E5F8B5793";
            String iv = "508FAF6C53475545EC640D73F0778393";
            Console.WriteLine("\nValor de B enviado pelo professor: " + b.ToString());
            Console.WriteLine("\nMensagem enviada pelo professor: " +  msg.ToString());
            Console.WriteLine("\nIV da mensagem do professor: " + iv.ToString());
            String msg_padded = msg.Replace(iv,String.Empty);
            Console.WriteLine("\n Mensagem após o padding: " + msg_padded);

            // Calcular V fazendo o cálculo b^a mod p
            BigInteger v = CalculateModulus(b, a, p);
            Console.WriteLine("\nValor de V calculado: " + v.ToString());
            String vHexa = ConvertToHex(v);
            Console.WriteLine($"\nValor de V em Hexadecimal: {vHexa}");

            // Calcular o Hash SHA256
            byte[] S = CalculateSHA256(v);
            byte[] key = new byte[16];
            Array.Copy(S, key, 16);

            Console.WriteLine("\nValor do Hash S: " + BitConverter.ToString(S).Replace("-", "").ToLower());

            // Chave são os primeiros 128 bits, ou seja, os primeiros 16 bytes
            string keyHash = BitConverter.ToString(key).Replace("-", "").ToLower();
            Console.WriteLine("\nValor da Chave em String: " + keyHash);

            // Descriptografar a mensagem
            string descryptedText = DecryptText(msg_padded, keyHash, iv);
            Console.WriteLine("\nTexto descriptografado: " + descryptedText);

            // Inverter o texto descriptografado
            char[] textArray = descryptedText.ToCharArray();
            Array.Reverse(textArray);
            string textReverse = new string(textArray);
            Console.WriteLine("\nTexto invertido: " + textReverse);

            // Encriptar a mensagem para enviar ao professor
            string encriptedText = EncryptText(textReverse,keyHash);
            Console.WriteLine("\nTexto invertido criptografado: " + encriptedText);
            
            // Texto sem IV
            string encriptedTextNoIV = encriptedText.Substring(32);
            Console.WriteLine("\nTexto invertido criptografado sem IV: " + encriptedTextNoIV);

        }

        /**
         * Método para geração de um valor primo para usarmos no programa
         */
        public static BigInteger GeneratePrime(int digits)
        {
            BigInteger minValue = (BigInteger)Math.Pow(10, digits - 1);
            BigInteger maxValue = (BigInteger)Math.Pow(10, digits) - 1;

            Random rand = new Random();
            BigInteger number = GenerateRandomBigInteger(minValue,maxValue,rand);
            while (!IsPrime(number))
            {
                number = GenerateRandomBigInteger(minValue, maxValue, rand);
            }
            return number;
        }

        /**
         * Método para verificar se o valor é primo ou não
         * Ele é muito lento porque vai verificando cada valor até o biginteger original
         */
        private static bool IsPrime(BigInteger number)
        {
           if(number < 2)
            {
                return false;
            }
           if(number == 2 || number == 3)
            {
                return true;
            }
           double value = Math.Sqrt((double )number);
           BigInteger valueTrans = (BigInteger)value;
           for(BigInteger i = 2; i <= valueTrans; i++)
            {
                if (number % i == 0)
                {
                    //Console.WriteLine("Valor não é primo");
                    return false;
                }
            }
            //Console.WriteLine("Valor é primo");
            return true;
        }

        /**
         * Método para gerar um biginteger aleatório para uso inicial
         */
        private static BigInteger GenerateRandomBigInteger(BigInteger minValue, BigInteger maxValue, Random random)
        {
            int maxBytes = (int)Math.Ceiling(BigInteger.Log(maxValue, 256));
            byte[] bytes = new byte[maxBytes];
            random.NextBytes(bytes);
            bytes[bytes.Length - 1] &= (byte)0x7F; // verifica se o bit maior não foi setado
            BigInteger result = new BigInteger(bytes);

            return BigInteger.Remainder(result, maxValue - minValue + 1) + minValue;
        }

        /**
         * Método para converter Biginteger em Hexadecimal
         */
        public static string ConvertToHex(BigInteger number)
        {
            return number.ToString("X");
        }

        /**
         * Método para converter Byte array para String
         */
        public static string ConvertByteToString(byte[] value)
        {
            String exit = BitConverter.ToString(value).Replace("-","");
            return exit;
        }

        /**
         * Método para converter String para byte array na Descriptografia
         * Foi preciso fazer separados devido a um erro no código C# devido ao tamanho máximo
         * da biblioteca de conversão em byte[]
         */
        public static byte[] ConvertStringToByteArray(String value)
        {
            if (value.Length % 2 != 0)
            {
                throw new ArgumentException("Invalid hexadecimal string: Length must be even. " + value);
            }

            string cleanedText = value;

            int length = cleanedText.Length;
            byte[] bytes = new byte[length / 2];

            for (int i = 0; i < length; i+=2)
            {
                bytes[i/2] = Convert.ToByte(cleanedText.Substring(i,2),16);
            }
            return bytes;
        }

        /**
         * Método para converter String em um byte Array no momento da encriptação da mensagem
         */
        public static byte[] ConvertStringToByteArrayEncrypt(String value)
        {
            if (value.Length % 2 != 0)
            {
                throw new ArgumentException("Invalid hexadecimal string: Length must be even. " + value);
            }

            char[] charArray = value.ToCharArray();

            byte[] byteArray = new byte[charArray.Length];
            for (int i = 0; i < charArray.Length; i++)
            {
                byteArray[i] = (byte)charArray[i];
            }
            return byteArray;
        }


        /**
         * Método para converter Hexadecimal para BigInteger
         */
        public static BigInteger ConvertHexToBigInteger(string hexString)
        {
            BigInteger value = BigInteger.Parse(hexString, NumberStyles.HexNumber);
            return value;
        }

        /**
         * Método para converter String para BigInteger
         */
        public static BigInteger ConvertStringToBigInteger(string numberString)
        {
            BigInteger result;
            if (BigInteger.TryParse(numberString, out result))
            {
                return result;
            }
            else
            {
                // Handle parsing failure
                throw new ArgumentException("Invalid BigInteger string.");
            }
        }

        /**
         * Método para calcular o módulo (G^a mod p) e (B^a mod p) 
         * para determinar a chave pública A para o professor e determinar o 
         * valor V para determinar o hash SHA256 para determinar a chave
         */
        public static BigInteger CalculateModulus(String g, BigInteger a, String p)
        {
            BigInteger modulus = ConvertHexToBigInteger(p);
            Console.WriteLine("\nValor de p convertido: " + modulus.ToString());
            BigInteger baseMod = ConvertHexToBigInteger(g);
            Console.WriteLine("\nValor de g convertido: " + baseMod.ToString());
            BigInteger calc = BigInteger.ModPow(baseMod, a, modulus); // base^exponent mod modulus
            return calc;
        }

        /**
         * Método para calcular o SHA256 a partir de um biginteger sendo ele o V
         * calculado, é feito uma quebra em byte verificando tamanho 256
         */

        public static byte[] CalculateSHA256(BigInteger value)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] valueBytes = value.ToByteArray();

                // Remove leading zero byte if present
                if (valueBytes.Length > 1 && valueBytes[0] == 0)
                    valueBytes = valueBytes.Skip(1).ToArray();

                // Reverse the byte order to little-endian
                Array.Reverse(valueBytes);

                byte[] hashBytes = sha256.ComputeHash(valueBytes);

                return hashBytes;
            }
        }

        /**
         * Método para descriptografar uma mensagem de texto criptografado, utilizado o padding PKCS7
         * Teve alguns problemas na conversão de byte, mas com a biblioteca AES do C# achei uma solução
         */
        public static string DecryptText(string msg_padded, string key, string iv)
        {
            byte[] ciphertext = ConvertStringToByteArray(msg_padded);
            string plaintext = "";
            byte[] ivBytes = ConvertStringToByteArray(iv);
            byte[] keyBytes = ConvertStringToByteArray(key);
            using (Aes aes = Aes.Create())
            {
                aes.Key = keyBytes;
                aes.IV = ivBytes;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                ICryptoTransform decryptor = aes.CreateDecryptor();

                using (MemoryStream msDecrypt = new MemoryStream(ciphertext))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            plaintext = srDecrypt.ReadToEnd();
                            return plaintext;
                        }
                    }
                }
            }
        }

        /**
         * Método de encriptografia do texto reverso (pequeno problema no padding causando
         * um retorno além devido ao tamanho do bloco do texto
         */
        public static string EncryptText(string msg, string key)
        {
            for (;msg.Length < 108;)
            {
                msg = "00" + msg;
            }
            if (msg.Length % 2 != 0) msg = "0" + msg;
            byte[] plaintext = ConvertStringToByteArrayEncrypt(msg);
            byte[] keyBytes = ConvertStringToByteArray(key);
            using (Aes aes = Aes.Create())
            {
                aes.Key = keyBytes;
                byte[] iv = GenerateIV();
                Console.WriteLine("\nIV gerado: " + ConvertByteToString(iv));
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                ICryptoTransform encryptor = aes.CreateEncryptor();

                using (MemoryStream memoryStream = new MemoryStream())
                {
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(plaintext, 0, plaintext.Length);
                        cryptoStream.FlushFinalBlock();
                    }

                    byte[] encryptedBytes = memoryStream.ToArray();
                    return ByteArrayToString(iv) + ByteArrayToString(encryptedBytes);
                }
            }
        }


        /**
         * Conversor de String para hexadecimal
         */
        public static string ConvertStringToHex(string text)
        {
            StringBuilder sb = new StringBuilder();
            foreach (char c in text)
            {
                sb.Append(((int)c).ToString("X2"));
            }

            return sb.ToString();
        }

        /**
         * Gerador de um IV aleatório para a mensagem de retorno ao professor
         */
        static byte[] GenerateIV()
        {
            using (Aes aes = Aes.Create())
            {
                aes.GenerateIV();
                return aes.IV;
            }
        }

        /**
         * Conversor de Byte Array para String
         */
        static string ByteArrayToString(byte[] bytes)
        {
            StringBuilder sb = new StringBuilder(bytes.Length * 2);
            foreach (byte b in bytes)
            {
                sb.AppendFormat("{0:x2}", b);
            }
            return sb.ToString();
        }
    }
}