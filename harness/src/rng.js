/**
 * Deterministic PRNG for *non-secret* test material (ids, pseudonyms, nonces, seeds).
 *
 * WHY: the harness must be reproducible so that a reviewer re-running it gets the
 * same credential population and the same leak table. Everything that is not
 * required to be unpredictable is derived from a fixed seed here.
 *
 * WHAT IS NOT SEEDED: BBS `ProofGen` randomness. The BBS library draws its own
 * entropy from WebCrypto and we deliberately do not touch it -- test (c) in the
 * harness asserts that derived proofs differ on every presentation, which is only
 * meaningful if the library's real randomness is in play. So proof bytes (and only
 * proof bytes) differ between runs; the report prints flags, not raw proof bytes.
 */
import {createHash} from 'node:crypto';

export class DeterministicRng {
  constructor(seed = 'open-core-p1') {
    this.state = createHash('sha256').update(String(seed)).digest();
    this.counter = 0;
  }

  /** Next 32 deterministic bytes. */
  bytes(n = 32) {
    const out = Buffer.alloc(n);
    let filled = 0;
    while(filled < n) {
      this.state = createHash('sha256')
        .update(this.state)
        .update(Buffer.from([this.counter++ & 0xff]))
        .digest();
      const take = Math.min(32, n - filled);
      this.state.copy(out, filled, 0, take);
      filled += take;
    }
    return new Uint8Array(out);
  }

  hex(n = 16) {
    return Buffer.from(this.bytes(n)).toString('hex');
  }

  /** RFC-4122-shaped (but deterministic) urn:uuid string. */
  uuid() {
    const h = this.hex(16);
    return `urn:uuid:${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-a${h.slice(17, 20)}-${h.slice(20, 32)}`;
  }

  int(maxExclusive) {
    const b = this.bytes(4);
    const v = (b[0] << 24 >>> 0) + (b[1] << 16) + (b[2] << 8) + b[3];
    return v % maxExclusive;
  }
}
