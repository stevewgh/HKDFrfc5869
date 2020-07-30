using System;
using System.Security.Cryptography;

namespace HKDFrfc5869
{
    /// <summary>
    /// HMAC based Extract-and-Expand Key Derivation Class
    /// </summary>
    public sealed class HKDF : IDisposable
    {
        private bool disposed = false;
        private readonly HMACProvider hmacProvider;

        /// <summary>
        /// 
        /// </summary>
        /// <param name="algo"></param>
        public HKDF(HashAlgorithmName algo)
        {
            this.hmacProvider = new HMACProvider(algo);
        }

        /// <summary>
        /// HMAC based Extract-and-Expand Key Derivation Function which returns cryptographically random keying material.
        /// </summary>
        /// <param name="inputKeyingMaterial">Secret: The input keying material is not necessarily distributed uniformly, and the attacker may have some partial knowledge about it (for example, a Diffie-Hellman value computed by a key exchange protocol) or even partial control of it (as in some entropy-gathering applications).</param>
        /// <param name="salt">Non Secret: Optional salt value (a non-secret random value). If not provided, zeros are used.</param>
        /// <param name="info">Non Secret: Optional value which may contain a protocol number, algorithm identifiers, user identities, etc which can be used to derive different keys when the same <paramref name="inputKeyingMaterial"/> is used for two different purposes</param>
        /// <param name="outputLength">Optional length of output keying material. If not provided, the output keying material will match the digest length of the HashAlgorithm requested.</param>
        /// <returns></returns>
        public byte[] DeriveKey(byte[] inputKeyingMaterial, byte[] salt = null, byte[] info = null, int? outputLength = null)
        {
            CheckIfDisposed();

            if(inputKeyingMaterial == null || inputKeyingMaterial.Length == 0)
            {
                throw new ArgumentOutOfRangeException(nameof(inputKeyingMaterial), "Must be non null and have a non zero length");
            }

            if (!outputLength.HasValue)
            {
                outputLength = this.hmacProvider.DigestLength;
            }

            int maxAllowedDigestLength = 255 * this.hmacProvider.DigestLength;

            if (outputLength < 0 || outputLength > maxAllowedDigestLength)
            {
                throw new ArgumentOutOfRangeException(nameof(outputLength), outputLength, $"Output length must be between 1 and {maxAllowedDigestLength}");
            }

            return Expand(Extract(inputKeyingMaterial, salt), outputLength.Value, info);
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
                salt = new byte[this.hmacProvider.DigestLength];
            }

            return this.hmacProvider.HMAC(salt, ikm);
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
                resultBlock = this.hmacProvider.HMAC(prk, currentInfo);
                Array.Copy(resultBlock, 0, result, len - bytesRemaining, Math.Min(resultBlock.Length, bytesRemaining));
                bytesRemaining -= resultBlock.Length;
            }

            return result;
        }

        void Dispose(bool disposing)
        {
            if (!disposed)
            {
                if(disposing)
                {
                    this.hmacProvider.Dispose();
                }

                disposed = true;
            }
        }

        /// <summary>
        /// 
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
        }
    }
}