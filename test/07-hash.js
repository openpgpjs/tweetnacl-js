import nacl from '../nacl-fast.js';
import naclUtil from 'tweetnacl-util';
import test from 'tape';

import randomVectors from './data/hash.random.js';

const enc = naclUtil.encodeBase64,
    dec = naclUtil.decodeBase64;

// nacl.hash not exposed, hash result checked by signing tests
test('nacl.hash random test vectors', {skip: true}, function(t) {
  randomVectors.forEach(function(vec) {
    var msg = dec(vec[0]);
    var goodHash = dec(vec[1]);
    var hash = nacl.hash(msg);
    t.equal(enc(hash), enc(goodHash));
  });
  t.end();
});
