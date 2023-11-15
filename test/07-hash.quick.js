import nacl from '../nacl-fast.js';
import naclUtil from 'tweetnacl-util';
import test from 'tape';

import specVectors from './data/hash.spec.js';

const enc = naclUtil.encodeBase64;

// nacl.hash not exposed, hash result checked by signing tests
test('nacl.hash length', {skip: true}, function(t) {
  t.equal(nacl.hash(new Uint8Array(0)).length, 64);
  t.equal(nacl.hash(new Uint8Array(100)).length, 64);
  t.end();
});

test('nacl.hash exceptions for bad types', {skip: true}, function(t) {
  t.throws(function() { nacl.hash('string'); }, TypeError, 'should throw TypeError for string type');
  t.throws(function() { nacl.hash([1,2,3]); }, TypeError, 'should throw TypeError for array type');
  t.end();
});

test('nacl.hash specified test vectors', {skip: true}, function(t) {
  specVectors.forEach(function(vec) {
    var goodHash = new Uint8Array(vec[0]);
    var msg = new Uint8Array(vec[1]);
    var hash = nacl.hash(msg);
    t.equal(enc(hash), enc(goodHash));
  });
  t.end();
});
