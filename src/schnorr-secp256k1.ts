import {
  createForeignCurve,
  Crypto,
  CanonicalForeignField,
  ForeignCurve,
} from 'o1js';

// Define Secp256k1 curve
class Secp256k1Curve extends createForeignCurve(Crypto.CurveParams.Secp256k1) {}

export { SchnorrSecp256k1, Secp256k1Curve };

class SchnorrSecp256k1 {
  // Generator point G
  private static G = Secp256k1Curve.generator;

  /**
   * Generates a new Schnorr key pair
   *
   * @returns {Object} Key pair containing private and public keys
   */
  static generateKeyPair(): {
    privateKey: CanonicalForeignField;
    publicKey: ForeignCurve;
  } {
    // Generate random private key
    const privateKey = Secp256k1Curve.Scalar.random();
    // Compute public key as P = dG
    const publicKey = SchnorrSecp256k1.G.scale(privateKey);

    return { privateKey, publicKey };
  }
}
