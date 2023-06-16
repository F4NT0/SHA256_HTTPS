using System;
using System.Collections;
using System.ComponentModel;
using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace T3Seguranca {
    public class Program {
          public static void Main(string[] args)
        {
            // Gerar um novo número primo para ser usado no programa
            //BigInteger a = GeneratePrime(30); // número primo de 30 dígitos
            //Console.WriteLine("Valor primo gerado: " + a.ToString());

            // Valor gerado: 302169981172443897262726089341
            //BigInteger a = BigInteger.Parse("302169981172443897262726089341");
            BigInteger a = BigInteger.Parse("332201154371599461561800595396");
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
            //String b = "6C7204F6E00ACEC265BF290F04B636A042A42A4274B066EFC8D50E72A957792BF49FD43A71B426C7CF7B6F5D144ECDF28F917154DF0BABEA437011BE4BD8FB62F940AB576140CD5675F93435CA5A8BCF1B38FE7B3942E8A8D8B9B6155727C60E034F26537BD3DE31BDE997D369032C3DD115ACB03A896C945B399A44F5517D8B";
            String b = "0090CB4B809291A9A9358DE46CA24D67836229CE437EDFE131514D02B6ECA8E7785DFB5B0BCB65F255259AFE65E314F0854F3A00C940249AA7D1CD73637722C3CF789948736CA25E2B57B8157693CBD01D77C70FBA179FAAC5147CD6D7CF37A5548B247D12172A73E95DFB8E61AEA8BBC35D6761A9300D3AC55EE58706B2ADEAC8";
            //String msg = "830C77BD1E8432F48D7C29DA481EAD6DF4CEFEEF00D3AC15364472DE34D370A69C61B3BD1DF5AEE55783E2075486877636A43B824D66938D1785A54AAAA47EB35B96462D82B1501A78F24BBC5F5B5BF11229721113EC19CDA9402E4EA3A1D8AEB4B0A931F6AF9923F8D4AE7C6E92BB17";
            String msg = "2522592456943A9A74F0356395AF1C2CEF0936DCE855427110149B81DA044D215CDBB78D2840EDF152E61F3AC8A513126BA2C0E37CFCF580A0CAC638D8B5EB0BF5367A1558CCE5A46A2E13C0C42AF45E9872FF4C8B5A0E4A2B85CB4BD5F44064B3073933B29829FB5BB03CF57467DD2A";
            //String iv = "830C77BD1E8432F48D7C29DA481EAD6D";
            String iv = "2522592456943A9A74F0356395AF1C2C";
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

            // Calcular o Hash256
            //string S = CalculateSHA256(vHexa);
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
            

        }

        public static BigInteger GeneratePrime(int digits)
        {
            BigInteger minValue = (BigInteger)Math.Pow(10, digits - 1);
            BigInteger maxValue = (BigInteger)Math.Pow(10, digits) - 1;

            Random rand = new Random();
            BigInteger number = GenerateRandomBigInteger(minValue,maxValue,rand);
            //Console.WriteLine("Valor gerado: " + number.ToString());
            while (!IsPrime(number))
            {
                number = GenerateRandomBigInteger(minValue, maxValue, rand);
                //Console.WriteLine($"Gerando outro valor biginteger: " + number.ToString());
            }
            return number;
        }

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

        private static BigInteger GenerateRandomBigInteger(BigInteger minValue, BigInteger maxValue, Random random)
        {
            int maxBytes = (int)Math.Ceiling(BigInteger.Log(maxValue, 256));
            byte[] bytes = new byte[maxBytes];
            random.NextBytes(bytes);
            bytes[bytes.Length - 1] &= (byte)0x7F; // verifica se o bit maior não foi setado
            BigInteger result = new BigInteger(bytes);

            return BigInteger.Remainder(result, maxValue - minValue + 1) + minValue;
        }

        public static string ConvertToHex(BigInteger number)
        {
            return number.ToString("X");
        }

        public static string ConvertByteToString(byte[] value)
        {
            String exit = BitConverter.ToString(value).Replace("-","");
            return exit;
        }
        public static byte[] ConvertStringToByteArray(String value)
        {
            if (value.Length % 2 != 0)
            {
                throw new ArgumentException("Invalid hexadecimal string: Length must be even. " + value);
            }

            int length = value.Length;
            byte[] bytes = new byte[length/2];
            for(int i = 0; i < length; i+=2)
            {
                bytes[i/2] = Convert.ToByte(value.Substring(i,2),16);
            }
            return bytes;
        }

        public static BigInteger ConvertHexToBigInteger(string hexString)
        {
            BigInteger value = BigInteger.Parse(hexString, NumberStyles.HexNumber);
            return value;
        }

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

        public static BigInteger CalculateModulus(String g, BigInteger a, String p)
        {
            BigInteger modulus = ConvertHexToBigInteger(p);
            Console.WriteLine("\nValor de p convertido: " + modulus.ToString());
            BigInteger baseMod = ConvertHexToBigInteger(g);
            Console.WriteLine("\nValor de g convertido: " + baseMod.ToString());
            BigInteger calc = BigInteger.ModPow(baseMod, a, modulus); // base^exponent mod modulus
            return calc;
        }

        public static byte[] CalculateSHA256(BigInteger value)
        {
            using (SHA256 sha256 = SHA256.Create())
            {

                int byteSize = (int)Math.Ceiling(BigInteger.Log(value, 256));
                byte[] byteArray = new byte[byteSize];
                for(int i = 0; i < byteSize; i++)
                {
                    byteArray[i] = (byte)(value % 256);
                    value /= 256;
                }
                Array.Reverse(byteArray);

                Console.WriteLine("\n");
                byte[] hashBytes = sha256.ComputeHash(byteArray);

                //string hashString = BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
               
                return hashBytes;
            }
        }

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

                return plaintext;
            }
        }

        public static string EncryptText(string msg, string key)
        {
            byte[] plaintext = ConvertStringToByteArray(msg);
            byte[] keyBytes = ConvertStringToByteArray(key);
            using (Aes aes = Aes.Create())
            {
                aes.Key = keyBytes;
                byte[] iv = GenerateIV();
                Console.WriteLine("IV gerado: " + ConvertByteToString(iv));
                plaintext.Concat(iv);
                Console.WriteLine("Plaintext com o IV concatenado: " + plaintext);
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
                    return ByteArrayToString(encryptedBytes);
                }
            }
        }

        static byte[] GenerateIV()
        {
            using (Aes aes = Aes.Create())
            {
                aes.GenerateIV();
                return aes.IV;
            }
        }

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