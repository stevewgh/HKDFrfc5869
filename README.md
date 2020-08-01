# HKDF
A C# implementation of the rfc5869 HMAC based Extract-and-Expand Key Derivation Function (HKDF) (https://tools.ietf.org/html/rfc5869)

### Highlights
* Follows the algorithm and tests from https://tools.ietf.org/html/rfc5869
* Uses '''Span<byte>''' for high performance

## Getting started
```
Install-Package HKDFrfc5869
```

### Examples

1. Provide just the initial key material, use default values for other options

```c#
using HKDFrfc5869;

using var hkdf = new HKDF(HashAlgorithmName.SHA256);
var keyMaterial = hkdf.DeriveKey(new byte[1]);

```

2. Provide a salt

```c#
using HKDFrfc5869;

using var hkdf = new HKDF(HashAlgorithmName.SHA256);
var keyMaterial = hkdf.DeriveKey(new byte[1], salt: new byte[1]);

```

3. Provide a salt and info

```c#
using HKDFrfc5869;

using var hkdf = new HKDF(HashAlgorithmName.SHA256);
var keyMaterial = hkdf.DeriveKey(new byte[1], salt: new byte[1], info: new byte[1]);

```

4. Provide a salt, info and request that the material is 1024 bytes in length

```c#
using HKDFrfc5869;

using var hkdf = new HKDF(HashAlgorithmName.SHA256);
var keyMaterial = hkdf.DeriveKey(new byte[1], salt: new byte[1], info: new byte[1], outputLength: 1024);

```

5. Provide a salt, info and request that the material is 1024 bytes in length and use an alternative hash algorithm

```c#
using HKDFrfc5869;

using var hkdf = new HKDF(HashAlgorithmName.SHA512);
var keyMaterial = hkdf.DeriveKey(new byte[1], salt: new byte[1], info: new byte[1], outputLength: 1024);

```

### Limitations

The algorithm defined by rfc5869 requires a single byte to be used in the intermediate hashed values, this means that the hashing algorithm can be used a maximum of 255 times. 
If the required keying material size is greater than 255 x the hash size then an exception will be thrown.