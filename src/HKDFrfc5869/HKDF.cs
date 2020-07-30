using System;
using System.Security.Cryptography;

namespace HKDFrfc5869
{
    public sealed class HKDF : IDisposable
    {
        private bool disposed = false;
        private readonly HMAC hmac;
        private readonly int digestLength;

        public HKDF(HashAlgorithmName algo)
        {
            this.hmac = this.CreateHMACInstance(algo);
            this.digestLength = this.hmac.HashSize / 8;
        }

        public byte[] DeriveKey(byte[] inputKeyingMaterial, byte[] salt = null, byte[] info = null, int outputLength = 0)
        {
            CheckIfDisposed();

            if(inputKeyingMaterial == null || inputKeyingMaterial.Length == 0)
            {
                throw new ArgumentOutOfRangeException(nameof(inputKeyingMaterial), "Must be non null and have a non zero length");
            }

            if (outputLength == 0)
            {
                outputLength = digestLength;
            }

            int maxAllowedDigestLength = 255 * digestLength;

            if (outputLength < 0 || outputLength > maxAllowedDigestLength)
            {
                throw new ArgumentOutOfRangeException(nameof(outputLength), outputLength, $"Output length must be between 1 and {maxAllowedDigestLength}");
            }

            return Expand(Extract(inputKeyingMaterial, salt), outputLength, info);
        }

        private void CheckIfDisposed()
        {
            if(disposed)
            {
                throw new ObjectDisposedException("HKDF has been disposed");
            }
        }

        private byte[] Extract(byte[] ikm, byte[] salt)
        {
            if (salt == null)
            {
                salt = new byte[digestLength];
            }

            return this.HMAC(salt, ikm);
        }

        private byte[] Expand(byte[] prk, int len, byte[] info)
        {
            if (info == null)
            {
                info = new byte[0];
            }

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
                using (this.hmac) { }
                disposed = true;
            }
        }

        ~HKDF()
        {
            // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
            Dispose(false);
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
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

        private byte[] HMAC(byte[] key, byte[] message)
        {
            var hmac = this.hmac;
            hmac.Key = key;
            return hmac.ComputeHash(message);
        }
    }
}
