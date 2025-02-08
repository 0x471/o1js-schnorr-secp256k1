import {
  Bool,
  ZkProgram,
  Struct,
} from 'o1js';
import { schnorr, secp256k1 } from '@noble/curves/secp256k1';
import { bytesToHex } from '@noble/hashes/utils';
import {
  SchnorrBIP340Secp256k1,
  Secp256k1Curve,
} from './schnorr-bip340-secp256k1.js';
import { schnorrGetE } from './utils.js';

const PublicInput = Struct({
  publicKey: Secp256k1Curve,
  messageHash: Secp256k1Curve.Scalar.Canonical,
  signature: {
    r: Secp256k1Curve.Field.Canonical,
    s: Secp256k1Curve.Scalar.Canonical,
  },
});

let program = ZkProgram({
  name: 'verifyBIP340',
  publicInput: PublicInput,
  publicOutput: Bool,

  methods: {
    verifyBIP340: {
      privateInputs: [],
      async method(publicInput) {
        const { publicKey, messageHash, signature } = publicInput;
        const result = SchnorrBIP340Secp256k1.verify(
          publicKey,
          messageHash,
          signature
        );
        return { publicOutput: result };
      },
    },
  },
});

// Generate test inputs
let privateKey = schnorr.utils.randomPrivateKey();
let publicKeyPoint = {
  x: secp256k1.ProjectivePoint.fromPrivateKey(privateKey).px,
  y: schnorr.utils.lift_x(
    secp256k1.ProjectivePoint.fromPrivateKey(privateKey).px
  ).py,
};

// https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv
let msg = '243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89';
let auxRand =
  'C87AA53824B4D7AE2EB035A2B5BBBCCC080E76CDC6D1692C4B0B62D798E6D906';

// Test valid case first
console.log('\n=== Testing Valid Signature ===');
let signature = schnorr.sign(msg, privateKey, auxRand);
let messageHash = schnorrGetE(signature, msg, schnorr.getPublicKey(privateKey));
let signatureObj = {
  r: Secp256k1Curve.Field.from(BigInt('0x' + bytesToHex(signature.slice(0, 32)))),
  s: Secp256k1Curve.Scalar.from(BigInt('0x' + bytesToHex(signature.slice(32))))
};

// Debug logging
console.log('publicKeyPoint:', {
  x: publicKeyPoint.x.toString(),
  y: publicKeyPoint.y.toString(),
});
console.log('messageHash:', messageHash.toString());
console.log('signature r:', signatureObj.r.toBigInt().toString());
console.log('signature s:', signatureObj.s.toBigInt().toString());

// Constraints and overview of the program
let { verifyBIP340 } = await program.analyzeMethods();

console.log("Summary: ", verifyBIP340.summary());

// Compile the program
console.log('Compiling program...');
await program.compile();

let proof = await program.verifyBIP340({
  publicKey: Secp256k1Curve.from(publicKeyPoint),
  messageHash: Secp256k1Curve.Scalar.from(messageHash),
  signature: signatureObj,
});

// Run verification
console.log('Running verification...');
const proofVerify = await program.verify(proof.proof);
console.log('Proof verified? ', proofVerify);

// Test invalid case
// console.log('\n=== Testing Invalid Signature ===');
// let invalidMsg = '143F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89';
// let invalidMessageHash = schnorrGetE(signature, invalidMsg, schnorr.getPublicKey(privateKey));

// let invalidProof = await program.verifyBIP340({
//   publicKey: Secp256k1Curve.from(publicKeyPoint),
//   messageHash: Secp256k1Curve.Scalar.from(invalidMessageHash),
//   signature: signatureObj
// });

//console.log('Invalid signature verification result:', await program.verify(invalidProof.proof));
