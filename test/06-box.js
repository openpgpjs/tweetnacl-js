import nacl from '../nacl-fast.js';
import naclUtil from 'tweetnacl-util';
import test from 'tape';

const randomVectors = require('./data/box.random');

const enc = naclUtil.encodeBase64,
    dec = naclUtil.decodeBase64;

// not implemented
test('nacl.box random test vectors', {skip: true}, function(t) {
  var nonce = new Uint8Array(nacl.box.nonceLength);
  randomVectors.forEach(function(vec) {
    var pk1 = dec(vec[0]);
    var sk2 = dec(vec[1]);
    var msg = dec(vec[2]);
    var goodBox = dec(vec[3]);
    var box = nacl.box(msg, nonce, pk1, sk2);
    t.equal(enc(box), enc(goodBox));
    var openedBox = nacl.box.open(goodBox, nonce, pk1, sk2);
    t.equal(enc(openedBox), enc(msg));
  });
  t.end();
});
