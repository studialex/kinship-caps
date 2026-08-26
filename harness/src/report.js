/** Plain-text rendering of the harness output. No colour, so it diffs cleanly. */

export function table(rows, columns) {
  const widths = columns.map(c =>
    Math.max(c.header.length, ...rows.map(r => String(c.get(r) ?? '').length)));
  const line = ch => `+${widths.map(w => ch.repeat(w + 2)).join('+')}+`;
  const render = cells => `| ${cells.map((c, i) =>
    String(c ?? '').padEnd(widths[i])).join(' | ')} |`;
  return [
    line('-'),
    render(columns.map(c => c.header)),
    line('='),
    ...rows.map(r => render(columns.map(c => c.get(r)))),
    line('-')
  ].join('\n');
}

export const LEAK_COLUMNS = [
  {header: 'field (path in the payload)', get: r => r.path},
  {header: 'constant?', get: r => r.constant ? 'yes' : 'no'},
  {header: 'k', get: r => r.anonymitySet ?? '-'},
  {header: 'correlatable?', get: r => r.correlatable ? 'yes' : 'no'},
  {header: 'leak', get: r => r.leak},
  {header: 'note', get: r => r.note}
];

export function h1(s) {
  return `\n${'='.repeat(78)}\n${s}\n${'='.repeat(78)}`;
}
export function h2(s) {
  return `\n--- ${s} ${'-'.repeat(Math.max(0, 72 - s.length))}`;
}

export function renderAnalysis(a) {
  const out = [];
  out.push(h2(`Leak table: ${a.name}`));
  out.push('k = number of distinct dependents in the corpus sharing this value ' +
    '(k=1 -> exact linkage, k=cohort -> no narrowing)');
  out.push(table(a.table, LEAK_COLUMNS));

  out.push(`\n(c) proof randomisation: ${a.proofs.distinctProofs}/${a.proofs.totalProofs} ` +
    `derived proofs distinct, repeat-visit pairs exercised: ${a.proofs.repeatVisitPairs} ` +
    `-> ${a.proofs.pass ? 'PASS' : 'HARD FAIL (duplicate proof bytes)'}`);

  const c = a.clustering;
  out.push(`\nGeneric clustering adversary (no field allowlist, colluding verifiers):`);
  out.push(`  clusters recovered: ${c.clusterCount} (sizes ${c.clusterSizes.join(',')})`);
  out.push(`  transitive closure over all shared values: target cluster ` +
    `${c.targetClusterSize} payloads, precision ${c.precision.toFixed(2)}, ` +
    `recall ${c.recall.toFixed(2)}`);
  if(c.bestSingleField) {
    const b = c.bestSingleField;
    out.push(`  best SINGLE discriminating field: ${b.path} = ${b.value}`);
    out.push(`    -> groups ${b.clusterSize} payloads, precision ${b.precision.toFixed(2)}, ` +
      `recall ${b.recall.toFixed(2)}`);
  }
  out.push(`  -> ${c.exactLinkage
    ? 'EXACT LINKAGE: all of the target\'s presentations, and only those, are linked'
    : c.partialLinkage ? 'partial narrowing only' : 'no linkage recovered'}`);
  if(c.topEvidence.length) {
    out.push('  strongest linking evidence:');
    for(const e of c.topEvidence.slice(0, 5)) {
      out.push(`    ${String(e.linked).padStart(3)} payloads share  ${e.path} = ${e.value}`);
    }
  }

  if(a.collusion) {
    out.push(`\n(d) issuer + verifier collusion:`);
    for(const f of a.collusion.findings) {
      out.push(`  [${f.leak ? 'LEAK' : ' ok '}] ${f.check}: ${f.result}`);
    }
  }
  out.push(`\nVERDICT for this profile: ${a.verdict}`);
  return out.join('\n');
}

export function renderCrossHop(x) {
  const out = [];
  out.push(h2('(e) cross-hop: ' + x.label));
  if(x.correlators.length === 0) {
    out.push('  no value fragment (>=8 chars) is shared between the guardian\'s and ' +
      'the sub-carer\'s presentations for the target.');
  } else {
    out.push(table(x.correlators, [
      {header: 'shared atom', get: r => r.atom},
      {header: 'k', get: r => r.anonymitySet},
      {header: 'in every presentation?', get: r => r.persistent ? 'yes' : 'no'},
      {header: 'hop1 field', get: r => r.hop1Paths[0] ?? ''},
      {header: 'hop2 field', get: r => r.hop2Paths[0] ?? ''},
      {header: 'leak', get: r => r.hard ? 'Y' : (r.anonymitySet < r.cohortSize ? 'partial' : 'N')}
    ]));
  }
  out.push(`  (e) CROSS-HOP UNLINKABILITY: ${x.pass ? 'PASS' : 'FAIL'}` +
    (x.pass ? '' : ` -- ${x.hardCorrelators.length} correlator(s) uniquely identify the dependent`));
  return out.join('\n');
}
