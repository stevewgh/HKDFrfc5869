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
        /// HMAC based Extract-and-Expand Key Derivation Function which returns deterministic keying material with good entropy.
        /// </summary>
        /// <param name="inputKeyingMaterial">Secret: The input keying material is not necessarily distributed uniformly, and the attacker may have some partial knowledge about it (for example, a Diffie-Hellman value computed by a key exchange protocol) or even partial control of it (as in some entropy-gathering applications).</param>
        /// <param name="salt">Non Secret: Optional salt value (a non-secret random value). If not provided, zeros are used.</param>
        /// <param name="info">Non Secret: Optional value which may contain a protocol number, algorithm identifiers, user identities, etc which can be used to derive different keys when the same <paramref name="inputKeyingMaterial"/> is used for two different purposes</param>
        /// <param name="outputLength">Optional length of output keying material. If not provided, the output keying material will match the digest length of the HashAlgorithm requested.</param>
        /// <returns>Keying material of <paramref name="outputLength"/> length or the digest length of the HashAlgorithm requested if <paramref name="outputLength"/> is ommited</returns>
        public ReadOnlySpan<byte> DeriveKey(ReadOnlySpan<byte> inputKeyingMaterial, Span<byte> salt = default, Span<byte> info = default, int? outputLength = null)
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

            return Expand(Extract(inputKeyingMaterial, salt), info, outputLength.Value);
        }

        private void CheckIfDisposed()
        {
            if(disposed)
            {
                throw new ObjectDisposedException("HKDF has been disposed");
            }
        }

        private Span<byte> Extract(ReadOnlySpan<byte> inputKeyingMaterial, Span<byte> salt)
        {
            if (salt.IsEmpty)
            {
                salt = new byte[this.hmacProvider.DigestLength];
            }

            return this.hmacProvider.HMAC(salt, inputKeyingMaterial);
        }

        private ReadOnlySpan<byte> Expand(Span<byte> pseudoRandomKey, Span<byte> info, int outputLength)
        {
            if (info.IsEmpty)
            {
                info = new byte[0];
            }

            var hashedValue = new Span<byte>();
            var result = new Span<byte>(new byte[outputLength]);
            var bytesRemaining = outputLength;

            for (int i = 1; bytesRemaining > 0; i++)
            {
                var tumbledValue = new Span<byte>(new byte[hashedValue.Length + info.Length + 1]);
                hashedValue.CopyTo(tumbledValue);
                info.CopyTo(tumbledValue.Slice(hashedValue.Length, info.Length));
                tumbledValue[tumbledValue.Length - 1] = (byte)i;

                hashedValue = this.hmacProvider.HMAC(pseudoRandomKey, tumbledValue);
                
                int lengthToCopy = Math.Min(hashedValue.Length, bytesRemaining);
                hashedValue.Slice(0, lengthToCopy).CopyTo(result.Slice(outputLength - bytesRemaining, lengthToCopy));

                bytesRemaining -= hashedValue.Length;
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