import nacl from '../nacl-fast.js';
import naclUtil from 'tweetnacl-util';
import test from 'tape';

test('nacl.randomBytes', function(t) {
  t.plan(1);
  // `nacl.randomBytes is no longer exported, but it's internally used for key generation
  const randomBytes = () => nacl.sign.keyPair().secretKey;
  var set = {}, s, i;
  for (i = 0; i < 1000; i++) {
    s = naclUtil.encodeBase64(randomBytes());
    if (set[s]) {
      t.fail('duplicate random sequence! ', s);
      return;
    }
    set[s] = true;
  }
  t.pass('no collisions');
});
