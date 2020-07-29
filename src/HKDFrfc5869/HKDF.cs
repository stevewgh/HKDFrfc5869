using System;
using System.Security.Cryptography;

namespace HKDFrfc5869
{
    public sealed class HKDF : IDisposable
    {
        private bool disposed = false;
        //private readonly HashAlgorithmName algorithm;
        private readonly HMAC hmac;

        public HKDF(HashAlgorithmName algo)
        {
            this.hmac = this.determineHMAC(algo);
            //this.digestLength = this.hmac.ComputeHash(ikm).Length;
        }

        public byte[] DeriveKey(byte[] salt, byte[] ikm, byte[] info, int outputLength = 0)
        {
            var digestLength = this.hmac.HashSize / 8;

            if (outputLength == 0)
            {
                outputLength = this.hmac.HashSize / 8;
            }

            if (outputLength < 0 || outputLength > 255 * digestLength)
            {
                throw new Exception("Bad output length requested of HKDF");
            }

            if (info == null)
            {
                info = new byte[0];
            }

            var prk = Extract(salt, ikm);

            if (prk.Length < digestLength)
            {
                throw new Exception("Psuedo-random key is larger then digest length. Cannot perform operation");
            }

            var result = Expand(prk, outputLength, info);
            return result;
        }

        internal byte[] Extract(byte[] ikm, byte[] salt)
        {
            var digestLength = this.hmac.HashSize / 8;

            if (salt == null)
            {
                salt = new byte[digestLength];
            }

            return this.HMAC(salt, ikm);
        }

        internal byte[] Expand(byte[] prk, int len, byte[] info)
        {
            var resultBlock = new byte[0];
            var result = new byte[len];
            var bytesRemaining = len;

            for (int i = 1; bytesRemaining > 0; i++)
            {
                var currentInfo = new byte[resultBlock.Length + info.Length + 1];
                Array.Copy(resultBlock, 0, currentInfo, 0, resultBlock.Length);
                Array.Copy(info, 0, currentInfo, resultBlock.Length, info.Length);
                currentInfo[currentInfo.Length - 1] = (byte)i;
                resultBlock = this.HMAC(prk, currentInfo);
                Array.Copy(resultBlock, 0, result, len - bytesRemaining, Math.Min(resultBlock.Length, bytesRemaining));
                bytesRemaining -= resultBlock.Length;
            }

            return result;
        }

        void Dispose(bool disposing)
        {
            if (!disposed)
            {
                if (disposing)
                {
                    // TODO: dispose managed state (managed objects).
                }

                // TODO: free unmanaged resources (unmanaged objects) and override a finalizer below.
                // TODO: set large fields to null.

                disposed = true;
            }
        }

        // TODO: override a finalizer only if Dispose(bool disposing) above has code to free unmanaged resources.
        // ~HKDF()
        // {
        //   // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
        //   Dispose(false);
        // }

        public void Dispose()
        {
            Dispose(true);
            // TODO: uncomment the following line if the finalizer is overridden above.
            // GC.SuppressFinalize(this);
        }

        private HMAC determineHMAC(HashAlgorithmName algorithm)
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

            return new HMACSHA256();
        }

        private byte[] HMAC(byte[] key, byte[] message)
        {
            var hmac = this.hmac;
            hmac.Key = key;
            return hmac.ComputeHash(message);
        }
    }
}
