/**
 * THE LINKABILITY HARNESS.
 *
 * Input: a corpus of presentation payloads -- exactly the bytes verifiers receive
 *        -- each tagged with ground truth (which dependent it really came from,
 *        which verifier it went to). Ground truth is used ONLY to score the
 *        adversary afterwards; the adversary itself never sees it.
 *
 * Checks implemented (letters match the brief):
 *   (a) element-by-element comparison across all presentations
 *   (b) flag values that are constant across a subject's presentations AND single
 *       that subject out of the cohort -> linkability leak
 *   (c) sanity: every BBS derived proof must be unique (randomised)
 *   (d) collusion: give the adversary what the ISSUER knows and re-test
 *   (+) a generic clustering adversary that uses NO field allowlist: it links any
 *       two presentations that agree on any leaf value with discriminating power,
 *       then we score the recovered partition against ground truth.
 *
 * IMPORTANT INTERPRETATION RULE. "Constant" is not the same as "leaking". The
 * scheme type string, the issuer key and a bucketed expiry are constant too, but
 * every dependent in the cohort shows the same value, so they narrow the
 * anonymity set to the whole cohort. What matters is the ANONYMITY SET SIZE k:
 * the number of distinct dependents in the corpus that share the subject's value
 * at that field. k == 1 is a hard leak; 1 < k < cohort is narrowing.
 */
import {unb64, verifyProof} from './bbs.js';

/* ------------------------------- (a) flatten ------------------------------ */

/**
 * Flatten a payload to `path -> string value`. Disclosed BBS messages are keyed
 * by their attribute name rather than their message index so the table reads.
 */
export function flatten(obj, prefix = '', out = new Map()) {
  for(const [k, v] of Object.entries(obj)) {
    const path = prefix ? `${prefix}.${k}` : k;
    if(v && typeof v === 'object' && !Array.isArray(v)) {
      flatten(v, path, out);
    } else if(Array.isArray(v)) {
      out.set(path, JSON.stringify(v));
    } else {
      const s = String(v);
      // relabel `...disclosedMessages.3` -> `...disclosed[valid_until]`
      const m = /^(.*)disclosedMessages\.\d+$/.exec(path);
      if(m && s.includes('=')) {
        out.set(`${m[1]}disclosed[${s.slice(0, s.indexOf('='))}]`, s);
      } else {
        out.set(path, s);
      }
    }
  }
  return out;
}

/* --------------------------- (b) leak table ------------------------------- */

/**
 * @param corpus   [{id, subject, verifierId, payload}]
 * @param target   subject id of dependent Y
 */
export function fieldTable({corpus, target}) {
  const flat = new Map(corpus.map(p => [p.id, flatten(p.payload)]));
  const subjects = [...new Set(corpus.map(p => p.subject))];
  const targetPres = corpus.filter(p => p.subject === target);
  const paths = new Set();
  for(const f of flat.values()) {
    for(const k of f.keys()) {
      paths.add(k);
    }
  }

  const rows = [];
  for(const path of [...paths].sort()) {
    const values = targetPres.map(p => flat.get(p.id).get(path));
    const present = values.filter(v => v !== undefined);
    if(present.length === 0) {
      continue;
    }
    const distinct = new Set(present);
    const constant = present.length === targetPres.length && distinct.size === 1;
    const value = constant ? present[0] : null;

    // How many *distinct dependents* in the whole corpus show this same value here?
    let k = null;
    let sharing = [];
    if(constant) {
      sharing = subjects.filter(s => corpus.some(
        p => p.subject === s && flat.get(p.id).get(path) === value));
      k = sharing.length;
    }

    const hardLeak = constant && k === 1 && subjects.length > 1;
    const narrowing = constant && k > 1 && k < subjects.length;

    rows.push({
      path,
      constant,
      anonymitySet: k,
      cohortSize: subjects.length,
      correlatable: hardLeak || narrowing,
      leak: hardLeak ? 'Y' : (narrowing ? 'partial' : 'N'),
      note: !constant ? 'varies per presentation'
        : hardLeak ? `unique to the subject (k=1 of ${subjects.length}) -- exact linkage`
          : narrowing ? `shared with ${k - 1} other dependent(s) -- anonymity set ${k}/${subjects.length}`
            : `cohort-wide (k=${k}/${subjects.length}) -- no narrowing`,
      sample: constant ? truncate(value) : truncate(present[0])
    });
  }
  return rows;
}

const truncate = (s, n = 46) =>
  s === undefined ? '' : (s.length > n ? `${s.slice(0, n)}...` : s);

/* ------------------------ (c) proof randomisation ------------------------- */

/** Every derived proof in the corpus must be distinct. Two equal proofs = hard fail. */
export function proofUniqueness({corpus}) {
  const seen = new Map();
  const collisions = [];
  let count = 0;
  for(const p of corpus) {
    for(const [path, v] of flatten(p.payload)) {
      if(!path.endsWith('proof')) {
        continue;
      }
      count++;
      if(seen.has(v)) {
        collisions.push({a: seen.get(v), b: `${p.id}.${path}`});
      } else {
        seen.set(v, `${p.id}.${path}`);
      }
    }
  }
  // Also confirm the two presentations sent to the SAME verifier differ.
  const byVerifier = new Map();
  for(const p of corpus) {
    const key = `${p.subject}|${p.verifierId}`;
    byVerifier.set(key, (byVerifier.get(key) ?? 0) + 1);
  }
  const repeats = [...byVerifier.values()].filter(n => n > 1).length;
  return {
    totalProofs: count, distinctProofs: seen.size,
    collisions, repeatVisitPairs: repeats,
    pass: collisions.length === 0
  };
}

/* --------------------- generic clustering adversary ----------------------- */

class UnionFind {
  constructor(ids) {
    this.p = new Map(ids.map(i => [i, i]));
  }
  find(x) {
    while(this.p.get(x) !== x) {
      this.p.set(x, this.p.get(this.p.get(x)));
      x = this.p.get(x);
    }
    return x;
  }
  union(a, b) {
    const ra = this.find(a);
    const rb = this.find(b);
    if(ra !== rb) {
      this.p.set(ra, rb);
    }
  }
}

/**
 * Colluding verifiers pool their payloads and link any two that agree on any
 * leaf value which is neither unique to one presentation nor common to all.
 * No knowledge of the schema, no allowlist of "suspicious" fields.
 */
export function clusteringAttack({corpus, target}) {
  const flat = new Map(corpus.map(p => [p.id, flatten(p.payload)]));
  const ids = corpus.map(p => p.id);
  const uf = new UnionFind(ids);
  const evidence = [];

  const SEP = String.fromCharCode(0); // cannot occur in a payload value
  const buckets = new Map(); // `path SEP value` -> [ids]
  for(const p of corpus) {
    for(const [path, v] of flat.get(p.id)) {
      const key = path + SEP + v;
      if(!buckets.has(key)) {
        buckets.set(key, []);
      }
      buckets.get(key).push(p.id);
    }
  }
  for(const [key, group] of buckets) {
    if(group.length < 2 || group.length === ids.length) {
      continue; // no discriminating power
    }
    const [path, value] = key.split(SEP);
    evidence.push({path, value: truncate(value), linked: group.length});
    for(let i = 1; i < group.length; i++) {
      uf.union(group[0], group[i]);
    }
  }

  const clusters = new Map();
  for(const id of ids) {
    const r = uf.find(id);
    if(!clusters.has(r)) {
      clusters.set(r, []);
    }
    clusters.get(r).push(id);
  }

  const targetIds = new Set(corpus.filter(p => p.subject === target).map(p => p.id));
  // The adversary's best guess about Y = the cluster containing Y's first payload.
  const first = corpus.find(p => p.subject === target).id;
  const guess = clusters.get(uf.find(first));
  const hit = guess.filter(i => targetIds.has(i)).length;
  const precision = hit / guess.length;
  const recall = hit / targetIds.size;

  /**
   * Transitive closure is a WEAK adversary: one broad field (e.g. the scope
   * string, shared by several dependents) merges everything and hides a perfect
   * correlator sitting right next to it. A real adversary picks the single most
   * selective field instead. So we also score the best individual (path, value).
   */
  let best = null;
  for(const [key, group] of buckets) {
    if(group.length < 2) {
      continue;
    }
    const h = group.filter(i => targetIds.has(i)).length;
    if(h === 0) {
      continue;
    }
    const p = h / group.length;
    const r = h / targetIds.size;
    const f1 = (p + r) === 0 ? 0 : (2 * p * r) / (p + r);
    if(!best || f1 > best.f1) {
      const sep = key.indexOf(SEP);
      best = {
        path: key.slice(0, sep), value: truncate(key.slice(sep + 1)),
        precision: p, recall: r, f1, clusterSize: group.length
      };
    }
  }
  const exactSingleField = !!best && best.precision === 1 && best.recall === 1 &&
    targetIds.size > 1;

  return {
    clusterCount: clusters.size,
    clusterSizes: [...clusters.values()].map(c => c.length).sort((a, b) => b - a),
    targetClusterSize: guess.length,
    targetPresentations: targetIds.size,
    precision, recall,
    bestSingleField: best,
    exactLinkage: exactSingleField ||
      (precision === 1 && recall === 1 && targetIds.size > 1),
    partialLinkage: !exactSingleField && recall > 1 / targetIds.size,
    // strongest single pieces of evidence, most linking first
    topEvidence: evidence.sort((a, b) => b.linked - a.linked).slice(0, 8)
  };
}

/**
 * CONJUNCTION adversary. The single-field adversary above misses the case where
 * no field is identifying on its own but several partial ones are, jointly.
 * This one keys every presentation by the tuple of ALL fields that are not
 * per-presentation random (a field qualifies if any of its values occurs in two
 * or more presentations), then links identical tuples. Still no allowlist.
 */
export function conjunctionAttack({corpus, target}) {
  const flat = new Map(corpus.map(p => [p.id, flatten(p.payload)]));
  const counts = new Map();
  for(const f of flat.values()) {
    for(const [path, v] of f) {
      const key = `${path}\u0000${v}`;
      counts.set(key, (counts.get(key) ?? 0) + 1);
    }
  }
  const stablePaths = new Set();
  for(const key of counts.keys()) {
    if(counts.get(key) >= 2) {
      stablePaths.add(key.slice(0, key.indexOf('\u0000')));
    }
  }
  // Colluding verifiers know which of them received each payload, so a field
  // that is a pure function of the receiving verifier (e.g. a length that only
  // depends on that verifier's nonce format) says nothing about the subject.
  // Drop fields that are constant within every verifier but differ across them.
  const verifierDetermined = path => {
    const byVerifier = new Map();
    for(const p of corpus) {
      const v = flat.get(p.id).get(path);
      if(!byVerifier.has(p.verifierId)) {
        byVerifier.set(p.verifierId, new Set());
      }
      byVerifier.get(p.verifierId).add(v);
    }
    const perVerifierConstant = [...byVerifier.values()].every(s => s.size === 1);
    const values = new Set([...byVerifier.values()].map(s => [...s][0]));
    return perVerifierConstant && values.size > 1;
  };
  const paths = [...stablePaths].filter(p => !verifierDetermined(p)).sort();
  const keyOf = id => JSON.stringify(paths.map(p => flat.get(id).get(p) ?? null));
  const targetIds = new Set(corpus.filter(p => p.subject === target).map(p => p.id));
  const tKey = keyOf([...targetIds][0]);
  const group = corpus.filter(p => keyOf(p.id) === tKey).map(p => p.id);
  const hit = group.filter(i => targetIds.has(i)).length;
  const subjectsInGroup = new Set(corpus.filter(p => group.includes(p.id)).map(p => p.subject));
  return {
    pathsUsed: paths.length,
    groupSize: group.length,
    subjectsInGroup: subjectsInGroup.size,
    precision: hit / group.length,
    recall: hit / targetIds.size,
    exactLinkage: subjectsInGroup.size === 1 && hit === targetIds.size && targetIds.size > 1
  };
}

/* --------------------------- (d) issuer collusion ------------------------- */

/**
 * The adversary is now verifiers + the ISSUER. The issuer contributes: every
 * original signature, every signed message (including the ones withheld from
 * verifiers), every credential's header, and the credential -> dependent map.
 *
 * @param issuerRecords  the issuer's full record set
 * @param headerMode     which signature variant this corpus was built from
 */
export async function collusionAttack({corpus, target, issuerRecords, headerMode,
  maxTrials = Infinity}) {
  const findings = [];
  const flat = new Map(corpus.map(p => [p.id, flatten(p.payload)]));
  const haystack = new Map(
    corpus.map(p => [p.id, [...flat.get(p.id).values()].join('')]));

  // d1: does any original BBS signature appear verbatim in any presentation?
  let sigHits = 0;
  for(const rec of issuerRecords) {
    const sigB64 = Buffer.from(rec.variants[headerMode].signature).toString('base64');
    for(const p of corpus) {
      if(haystack.get(p.id).includes(sigB64)) {
        sigHits++;
      }
    }
  }
  findings.push({
    check: 'd1 issuer signature bytes reappear in a presentation',
    result: sigHits === 0 ? 'no' : `YES (${sigHits} hits)`,
    leak: sigHits > 0
  });

  // d2: does any WITHHELD signed message value leak into a presentation?
  let msgHits = [];
  for(const rec of issuerRecords) {
    const variant = rec.variants[headerMode];
    for(const m of variant.messages) {
      const s = Buffer.from(m).toString('utf8');
      const val = s.slice(s.indexOf('=') + 1);
      if(val.length < 8) {
        continue; // too short to be a meaningful correlator
      }
      for(const p of corpus) {
        const disclosedHere = [...flat.get(p.id).keys()]
          .some(k => k.includes(`disclosed[${s.slice(0, s.indexOf('='))}]`));
        if(!disclosedHere && haystack.get(p.id).includes(val)) {
          msgHits.push({presentation: p.id, attribute: s.slice(0, s.indexOf('='))});
        }
      }
    }
  }
  msgHits = dedupe(msgHits);
  findings.push({
    check: 'd2 an undisclosed signed attribute value appears in the payload anyway',
    result: msgHits.length === 0 ? 'no' :
      `YES (${msgHits.length}: ${[...new Set(msgHits.map(h => h.attribute))].join(', ')})`,
    leak: msgHits.length > 0
  });

  // d3: trial verification. The issuer knows every credential's header; it replays
  // each presentation against each candidate header and counts how many verify.
  // A count of 1 means the presentation is pinned to one credential -> to one
  // dependent, because the issuer holds the credential -> dependent map.
  const targetPres = corpus.filter(p => p.subject === target)
    .slice(0, Number.isFinite(maxTrials) ? maxTrials : undefined);
  const setSizes = [];
  for(const p of targetPres) {
    const bbsPart = p.payload.bbs ?? p.payload.parent;
    const idxs = bbsPart.disclosedIndexes.split(',').filter(x => x !== '').map(Number);
    const disclosed = idxs.map(i => Buffer.from(bbsPart.disclosedMessages[String(i)], 'utf8'))
      .map(b => new Uint8Array(b));
    let n = 0;
    for(const rec of issuerRecords) {
      const ok = await verifyProof({
        publicKey: rec.issuerPublicKey,
        proof: unb64(bbsPart.proof),
        header: rec.variants[headerMode].header,
        presentationHeader: unb64(bbsPart.presentationHeader),
        disclosedMessages: disclosed,
        disclosedMessageIndexes: idxs
      });
      if(ok) {
        n++;
      }
    }
    setSizes.push(n);
  }
  const minSet = Math.min(...setSizes);
  findings.push({
    check: 'd3 issuer trial-verification: candidate credentials that fit a presentation',
    result: `anonymity set ${setSizes.join('/')} of ${issuerRecords.length} credentials`,
    leak: minSet === 1 && issuerRecords.length > 1
  });

  return {
    findings,
    linked: findings.some(f => f.leak)
  };
}

function dedupe(arr) {
  const seen = new Set();
  return arr.filter(x => {
    const k = JSON.stringify(x);
    if(seen.has(k)) {
      return false;
    }
    seen.add(k);
    return true;
  });
}

/* ------------------------------ orchestration ----------------------------- */

export async function analyse({name, corpus, target, issuerRecords, headerMode}) {
  const table = fieldTable({corpus, target});
  const proofs = proofUniqueness({corpus});
  const clustering = clusteringAttack({corpus, target});
  const collusion = issuerRecords
    // 3 trial presentations is enough to show the anonymity set size; the check
    // costs a full BBS proof verification per (presentation x candidate credential).
    ? await collusionAttack({corpus, target, issuerRecords, headerMode, maxTrials: 3})
    : null;

  const hardLeaks = table.filter(r => r.leak === 'Y');
  const partials = table.filter(r => r.leak === 'partial');

  return {
    name, table, proofs, clustering, collusion, hardLeaks, partials,
    verdict: (!proofs.pass || hardLeaks.length > 0 || clustering.exactLinkage ||
      (collusion?.linked ?? false)) ? 'FALSIFIED' : 'NOT-FALSIFIED'
  };
}
