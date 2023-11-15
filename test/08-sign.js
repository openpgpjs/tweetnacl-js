import nacl from '../nacl-fast.js';
import naclUtil from 'tweetnacl-util';
import test from 'tape';

import specVectors from './data/sign.spec.js';

const enc = naclUtil.encodeBase64,
    dec = naclUtil.decodeBase64;

test('nacl.sign and nacl.sign.open specified vectors', function(t) {
  specVectors.forEach(function(vec) {
    var keys = nacl.sign.keyPair.fromSecretKey(dec(vec[0]));
    var msg = dec(vec[1]);
    var goodSig = dec(vec[2]);

    var signedMsg = nacl.sign(msg, keys.secretKey);
    t.equal(enc(signedMsg.subarray(0, 64)), enc(goodSig), 'signatures must be equal');
    // var openedMsg = nacl.sign.open(signedMsg, keys.publicKey);
    // t.equal(enc(openedMsg), enc(msg), 'messages must be equal');
  });
  t.end();
});

test('nacl.sign.detached and nacl.sign.detached.verify some specified vectors', function(t) {
  specVectors.forEach(function(vec, i) {
    // We don't need to test all, as internals are already tested above.
    if (i % 100 !== 0) return;

    var keys = nacl.sign.keyPair.fromSecretKey(dec(vec[0]));
    var msg = dec(vec[1]);
    var goodSig = dec(vec[2]);

    var sig = nacl.sign.detached(msg, keys.secretKey);
    t.equal(enc(sig), enc(goodSig), 'signatures must be equal');
    var result = nacl.sign.detached.verify(msg, sig, keys.publicKey);
    t.ok(result, 'signature must be verified');
  });
  t.end();
});
