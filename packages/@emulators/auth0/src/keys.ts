import { KeyObject } from "node:crypto";
import { exportJWK, generateKeyPair } from "jose";

// A single tenant signing key, generated once per process. All routes that
// sign or advertise keys (token, oidc-discovery) share this promise so the
// JWKS always matches the tokens.
export const keyPairPromise = generateKeyPair("RS256");
export const KID = "emulate-auth0-1";

export async function publicJwk(): Promise<Record<string, unknown>> {
  const { publicKey } = await keyPairPromise;
  const jwk = await exportJWK(publicKey);
  return { ...jwk, kid: KID, use: "sig", alg: "RS256" };
}

// jose generates CryptoKey instances; node:crypto signing needs KeyObjects.
// Convert and memoize both, plus a base64 DER certificate-less public key for
// SAML/WS-Fed <KeyInfo> blocks.
let nodeKeysPromise: Promise<{ privateKey: KeyObject; publicKey: KeyObject; publicDerB64: string }> | null = null;

export function nodeKeys(): Promise<{ privateKey: KeyObject; publicKey: KeyObject; publicDerB64: string }> {
  if (!nodeKeysPromise) {
    nodeKeysPromise = (async () => {
      const { privateKey, publicKey } = await keyPairPromise;
      // jose CryptoKey -> node KeyObject via the WebCrypto interop. Cast
      // through KeyObject.from's own parameter type to avoid depending on the
      // DOM `CryptoKey` lib type.
      type WebCryptoKey = Parameters<typeof KeyObject.from>[0];
      const priv = KeyObject.from(privateKey as unknown as WebCryptoKey);
      const pub = KeyObject.from(publicKey as unknown as WebCryptoKey);
      const derPub = pub.export({ type: "spki", format: "der" }) as Buffer;
      return { privateKey: priv, publicKey: pub, publicDerB64: derPub.toString("base64") };
    })();
  }
  return nodeKeysPromise;
}
