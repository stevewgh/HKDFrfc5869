using System;
using System.Security.Cryptography;

namespace HKDFrfc5869
{
    public sealed class HKDF : IDisposable
    {
        private bool disposed = false;
        private HashAlgorithmName hash;

        public HKDF(HashAlgorithmName hash)
        {
            this.hash = hash;
        }

        public byte[] Extract(byte[] ikm, byte[] salt)
        {
            throw new NotImplementedException();
        }

        public byte[] Expand(object actualPrk, int len, byte[] info)
        {
            throw new NotImplementedException();
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
    }
}
