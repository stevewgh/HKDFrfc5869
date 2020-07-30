namespace HKDFrfc5869
{
    using System;
    using System.Security.Cryptography;

    internal class HMACProvider : IDisposable
    {
        private readonly HMAC hmac;
        private bool disposed;

        public int DigestLength { get; }

        public HMACProvider(HashAlgorithmName algorithmName)
        {
            hmac = CreateHMACInstance(algorithmName);
            DigestLength = hmac.HashSize / 8;
        }

        public Span<byte> HMAC(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message)
        {
            hmac.Key = key.ToArray();
            return new Span<byte>(hmac.ComputeHash(message.ToArray()));
        }

        private HMAC CreateHMACInstance(HashAlgorithmName algorithm)
        {
            if (algorithm == HashAlgorithmName.MD5)
            {
                return new HMACMD5();
            }
            else if (algorithm == HashAlgorithmName.SHA1)
            {
                return new HMACSHA1();
            }
            else if (algorithm == HashAlgorithmName.SHA256)
            {
                return new HMACSHA256();
            }
            else if (algorithm == HashAlgorithmName.SHA384)
            {
                return new HMACSHA384();
            }
            else if (algorithm == HashAlgorithmName.SHA512)
            {
                return new HMACSHA512();
            }
            else
            {
                throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, "Unsupported HashAlgorithmName");
            }
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!disposed)
            {
                if (disposing)
                {
                    // dispose managed state (managed objects) - none in this class
                }

                // free unmanaged resources (unmanaged objects) and override finalizer
                this.hmac.Dispose();
                disposed = true;
            }
        }

        ~HMACProvider()
        {
            // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
            Dispose(disposing: false);
        }

        public void Dispose()
        {
            // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }
    }
}
