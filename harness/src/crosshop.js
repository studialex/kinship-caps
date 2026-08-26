/**
 * (e) CROSS-HOP UNLINKABILITY.
 *
 * Question: given a presentation made BY THE GUARDIAN (hop 1) and a presentation
 * made BY THE SUB-CARER (hop 2), to different verifiers, can colluding verifiers
 * tell that both concern the same dependent Y?
 *
 * Path-and-value matching is too weak here: the same secret can surface under
 * different field names on either side of the delegation step -- e.g.
 * `guardian_key=` in hop 1 and `delegator_key=` in hop 2, or `credential_id=`
 * in hop 1 and `parent=` inside the sub-mandate's BBS header. So this check
 * compares ATOMS (path-agnostic value fragments) instead of whole leaf strings.
 *
 * Known limitation: atoms shorter than MIN_ATOM characters are ignored, because
 * short shared tokens ("N", "336", "2026") produce noise rather than linkage.
 * A low-entropy cross-hop correlator would therefore be missed here -- the
 * per-scenario field tables are what cover that case.
 */
import {flatten} from './harness.js';

const MIN_ATOM = 8;

/** Split a leaf value into candidate correlator atoms. */
export function atoms(value) {
  const out = new Set();
  if(value.length >= MIN_ATOM) {
    out.add(value);
  }
  for(const part of value.split('|')) {
    const eq = part.indexOf('=');
    const tail = eq >= 0 ? part.slice(eq + 1) : part;
    if(tail.length >= MIN_ATOM) {
      out.add(tail);
    }
  }
  return out;
}

function atomIndex(corpus) {
  // atom -> {subjects:Set, presentations:Set, paths:Set}
  const idx = new Map();
  for(const p of corpus) {
    for(const [path, value] of flatten(p.payload)) {
      for(const a of atoms(value)) {
        if(!idx.has(a)) {
          idx.set(a, {subjects: new Set(), presentations: new Set(), paths: new Set()});
        }
        const e = idx.get(a);
        e.subjects.add(p.subject);
        e.presentations.add(p.id);
        e.paths.add(path);
      }
    }
  }
  return idx;
}

/**
 * @param hop1 corpus of guardian presentations (all dependents)
 * @param hop2 corpus of sub-carer chain presentations (all dependents)
 * @param target dependent Y
 */
export function crossHopAnalysis({hop1, hop2, target, label}) {
  const all = [...hop1, ...hop2];
  const cohort = new Set(all.map(p => p.subject));
  const idx1 = atomIndex(hop1);
  const idx2 = atomIndex(hop2);
  const idxAll = atomIndex(all);

  const yHop1 = hop1.filter(p => p.subject === target);
  const yHop2 = hop2.filter(p => p.subject === target);

  const correlators = [];
  for(const [atom, e1] of idx1) {
    if(!e1.subjects.has(target)) {
      continue;
    }
    const e2 = idx2.get(atom);
    if(!e2 || !e2.subjects.has(target)) {
      continue; // does not cross the delegation step
    }
    const kSubjects = idxAll.get(atom).subjects.size;
    // does it appear in EVERY one of Y's presentations on both sides?
    const inAllHop1 = yHop1.every(p => e1.presentations.has(p.id));
    const inAllHop2 = yHop2.every(p => e2.presentations.has(p.id));
    correlators.push({
      atom: atom.length > 40 ? `${atom.slice(0, 40)}...` : atom,
      anonymitySet: kSubjects,
      cohortSize: cohort.size,
      persistent: inAllHop1 && inAllHop2,
      hop1Paths: [...e1.paths].slice(0, 3),
      hop2Paths: [...e2.paths].slice(0, 3),
      hard: kSubjects === 1 && cohort.size > 1
    });
  }

  const hard = correlators.filter(c => c.hard);
  return {
    label,
    cohortSize: cohort.size,
    sharedAtoms: correlators.length,
    hardCorrelators: hard,
    narrowingCorrelators: correlators.filter(
      c => !c.hard && c.anonymitySet < cohort.size),
    pass: hard.length === 0,
    correlators
  };
}
