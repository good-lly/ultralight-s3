type HashAlgorithm = 'sha256';
type Encoding = 'hex' | 'base64' | 'latin1';

interface Hmac {
  update(data: string | Buffer): void;
  digest(encoding?: Encoding): Promise<string>;
}

interface Hash {
  update(data: string | Buffer): void;
  digest(encoding?: Encoding): Promise<string>;
}

type HashFunction = (algorithm: HashAlgorithm) => Hash;
type HmacFunction = (algorithm: HashAlgorithm, key: string | Buffer) => Hmac;

let _createHmac: any = crypto.createHmac;
let _createHash: any = crypto.createHash;

if (typeof _createHmac === 'undefined' || typeof _createHash === 'undefined') {
  try {
    const isNode = typeof process !== 'undefined' && process.versions != null && process.versions.node != null;
    if (isNode) {
      // Import `crypto` from Node if available (useful for Node.js environments).
      const nodeCrypto = await import('node:crypto');
      _createHmac = nodeCrypto.createHmac;
      _createHash = nodeCrypto.createHash;
    } else {
      function concatUint8Arrays(arrays: Uint8Array[]): Uint8Array {
        const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
        const result = new Uint8Array(totalLength);
        let offset = 0;
        for (const arr of arrays) {
          result.set(arr, offset);
          offset += arr.length;
        }
        return result;
      }

      function encodeDigest(buffer: ArrayBuffer, encoding: String) {
        const hashArray = Array.from(new Uint8Array(buffer));

        if (encoding === 'hex') {
          return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        } else if (encoding === 'base64') {
          const binary = String.fromCharCode(...hashArray);
          return btoa(binary);
        } else if (encoding === 'latin1') {
          return String.fromCharCode(...hashArray);
        } else {
          throw new Error(`Unsupported encoding: ${encoding}`);
        }
      }

      // Browser-compatible `createHash` using `crypto.subtle` for SHA-256
      _createHash = (algorithm: string): any => {
        if (algorithm !== 'sha256') throw new Error('Only SHA-256 is supported in the browser.');

        const chunks: Uint8Array[] = [];

        return {
          update(data: string | Buffer) {
            const encoder = new TextEncoder();
            const encoded = typeof data === 'string' ? encoder.encode(data) : new Uint8Array(data);
            chunks.push(encoded);
            // Allow method chaining
            return this;
          },
          async digest(encoding = 'hex') {
            const concatenated = concatUint8Arrays(chunks);
            const hashBuffer = await crypto.subtle.digest('SHA-256', concatenated);
            return encodeDigest(hashBuffer, encoding);
          },
        };
      };

      // Browser-compatible `createHmac` using a polyfill approach (for HMAC).
      _createHmac = (algorithm: string, key: string | Buffer) => {
        if (algorithm !== 'sha256') throw new Error('Only SHA-256 HMAC is supported in the browser.');

        const chunks: Uint8Array[] = [];
        const encoder = new TextEncoder();
        const keyData = typeof key === 'string' ? encoder.encode(key) : new Uint8Array(key);

        let cryptoKeyPromise: Promise<CryptoKey> | null = null;

        function ensureCryptoKey() {
          if (!cryptoKeyPromise) {
            cryptoKeyPromise = crypto.subtle.importKey(
              'raw',
              keyData,
              { name: 'HMAC', hash: { name: 'SHA-256' } },
              false,
              ['sign'],
            );
          }
          return cryptoKeyPromise;
        }

        return {
          update(data: string | Buffer) {
            const encoded = typeof data === 'string' ? encoder.encode(data) : new Uint8Array(data);
            chunks.push(encoded);
            // Allow method chaining
            return this;
          },
          async digest(encoding = 'hex') {
            const cryptoKey = await ensureCryptoKey();
            const concatenated = concatUint8Arrays(chunks);
            const signature = await crypto.subtle.sign('HMAC', cryptoKey, concatenated);
            return encodeDigest(signature, encoding);
          },
        };
      };
    }
  } catch (e) {
    console.warn(
      'ultralight-s3 Module: Crypto functions are not available. Using SubtleCrypto for browser compatibility.',
    );
  }
}

export { _createHmac, _createHash };
