import {
  createForeignCurve,
  Crypto,
  CanonicalForeignField,
  ForeignCurve,
  Bool,
  AlmostForeignField} from 'o1js';
import { FlexiblePoint } from 'o1js/dist/node/lib/provable/crypto/foreign-curve';

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
   * @param {FlexiblePoint} publicKeyPoint - The public key P must be a valid x-coordinate lifted to a curve point `lift_x` ensures we have a valid curve point by computing the corresponding y-coordinate and choosing the even y-value as per BIP340/Schnorr specification
   * @param {AlmostForeignField} messageHash - Original message
   * @param {Object} signature - Signature containing R and s
   * @returns {Bool} True if signature is valid, False otherwise
   */
  static verify(
    publicKeyPoint: FlexiblePoint,
    messageHash: AlmostForeignField,
    signature: {
      r: AlmostForeignField;
      s: AlmostForeignField;
    }
  ): Bool {
    const curve = ForeignCurve.from(publicKeyPoint);
    
    // Calculate: sG = s * G
    const sG = SchnorrBIP340Secp256k1.G.scale(signature.s);

    // e = Hash(R.x || P.x || m)
    const e = messageHash;

    // Calculate: eP = e * P
    const eP = curve.scale(e);

    // Calculate: R = sG - eP
    const R = sG.add(eP.negate());

    // TODO, Check: is_infinite(R). Does o1js handle this check?

    // Check: R has even y-coordinate
    const isEvenY = R.y.toBits()[0].equals(Bool(true));

    // Check: R.x == r
    const hasMatchingX = R.x.equals(signature.r.toBigInt());

    return isEvenY.and(hasMatchingX);
  }
}
