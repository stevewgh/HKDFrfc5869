namespace HKDFrfc5869
{
    using System.Security.Cryptography;

    internal class HMACProvider
    {
        private HMAC hmac;

        public HMACProvider(HashAlgorithmName hash)
        {
            hmac = HMAC.Create(hash.Name);
        }
    }
}
