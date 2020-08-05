namespace HKDFrfc5869.Tests
{
    using System;
    using System.Linq;
    using System.Security.Cryptography;

    public class TestCaseData
    {
        public TestCaseData(HashAlgorithmName algorithm, string initialKeyingMaterial, string salt, string info, int length, string expectedKeyingMaterial)
        {
            this.Algorithm = algorithm;
            this.InitialKeyingMaterial = ToByteArray(initialKeyingMaterial);
            this.Salt = ToByteArray(salt);
            this.Info = ToByteArray(info);
            this.Length = length;
            this.ExpectedKeyingMaterial = ToByteArray(expectedKeyingMaterial);
        }

        public HashAlgorithmName Algorithm { get; }

        public byte[] InitialKeyingMaterial { get; }

        public byte[] Salt { get; }

        public byte[] Info { get; }

        public int Length { get; }

        public byte[] ExpectedKeyingMaterial { get; }

        private static byte[] ToByteArray(string hex)
        {
            if(hex == null)
            {
                return null;
            }

            return Enumerable.Range(0, hex.Length / 2).Select(x => Convert.ToByte(hex.Substring(x * 2, 2), 16)).ToArray();
        }
    }
}