import nacl from '../nacl-fast.js';
import naclUtil from 'tweetnacl-util';
import test from 'tape';

import specVectors from './data/onetimeauth.spec.js';

var enc = naclUtil.encodeBase64;

// not implemented
test('nacl.lowlevel.crypto_onetimeauth specified vectors', {skip: true}, function(t) {
  t.pass();
  var out = new Uint8Array(16);
  specVectors.forEach(function(v) {
    nacl.lowlevel.crypto_onetimeauth(out, 0, v.m, 0, v.m.length, v.k);
    t.equal(enc(out), enc(v.out));
  });
  t.end();
});
