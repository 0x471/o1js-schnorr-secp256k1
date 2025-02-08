import {
  createForeignCurve,
  Crypto,
  CanonicalForeignField,
  ForeignCurve,
  Bool,
} from 'o1js';

// Define Secp256k1 curve
class Secp256k1Curve extends createForeignCurve(Crypto.CurveParams.Secp256k1) {}

export { SchnorrBIP340Secp256k1, Secp256k1Curve };

class SchnorrBIP340Secp256k1 {
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
    // Generate: a random private key
    const privateKey = Secp256k1Curve.Scalar.random();
    // Calculate: P = d * G
    const publicKey = SchnorrBIP340Secp256k1.G.scale(privateKey);

    return { privateKey, publicKey };
  }

  // https://github.com/bitcoin/bips/blob/master/bip-0340
  /**
   * Verifies a Schnorr signature (BIP430)
   *
   * @param {ForeignCurve} publicKeyPoint - The public key P must be a valid x-coordinate lifted to a curve point `lift_x` ensures we have a valid curve point by computing the corresponding y-coordinate and choosing the even y-value as per BIP340/Schnorr specification
   * @param {CanonicalForeignField} messageHash - Original message
   * @param {Object} signature - Signature containing R and s
   * @returns {Bool} True if signature is valid
   */
  static verify(
    publicKeyPoint: ForeignCurve,
    messageHash: CanonicalForeignField,
    signature: { r: CanonicalForeignField; s: CanonicalForeignField }
  ): Bool {
    const curve = Secp256k1Curve.from(publicKeyPoint);

    // Calculate: sG = s * G
    const sG = SchnorrBIP340Secp256k1.G.scale(signature.s);

    // Calculate: eP = e * P
    const eP = curve.scale(messageHash);

    // Calculate: R = sG - eP
    const R = sG.add(eP.negate());

    // TODO, Check: is_infinite(R). Does o1js handle this check?

    // Check: R.x equals r
    R.x.assertEquals(signature.r);

    // Check: R.y is even
    R.y.toBits()[0].assertEquals(Bool(true));

    return Bool(true);
  }
}
