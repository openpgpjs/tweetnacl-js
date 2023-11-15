import nacl from '../nacl-fast.js';
import naclUtil from 'tweetnacl-util';
import test from 'tape';

import randomVectors from './data/secretbox.random.js';

var enc = naclUtil.encodeBase64,
    dec = naclUtil.decodeBase64;

// not implemented
test('nacl.secretbox random test vectors', {skip: true}, function(t) {
  randomVectors.forEach(function(vec) {
    var key = dec(vec[0]);
    var nonce = dec(vec[1]);
    var msg = dec(vec[2]);
    var goodBox = dec(vec[3]);
    var box = nacl.secretbox(msg, nonce, key);
    t.ok(box, 'box should be created');
    t.equal(enc(box), enc(goodBox));
    var openedBox = nacl.secretbox.open(goodBox, nonce, key);
    t.ok(openedBox, 'box should open');
    t.equal(enc(openedBox), enc(msg));
  });
  t.end();
});
