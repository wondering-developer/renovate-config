// Regression test for the Schema-A customManager regex in default.json.
//
// Why this exists: the original pattern required the `# renovate:` annotation on
// the line DIRECTLY above `imageDigest:`. A single explanatory comment (or the
// `imageVersion:` line) in between made the manager skip the image *silently* —
// no warning, no dashboard entry, just a digest that never gets bumped again.
// kubecloud's nextcloud image sat unpinned that way for weeks and accumulated
// 38 CRITICAL CVEs before a cluster-side Trivy sweep surfaced it.
//
// Run: node test/schema-a.test.mjs

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const config = JSON.parse(readFileSync(join(here, '..', 'default.json'), 'utf8'));

const schemaA = config.customManagers.find((m) =>
  m.matchStrings?.some((s) => s.includes('imageDigest')),
);
if (!schemaA) {
  console.error('FAIL: no customManager matching imageDigest found in default.json');
  process.exit(1);
}
const re = new RegExp(schemaA.matchStrings[0], 'g');

const DIGEST = 'sha256:' + 'a'.repeat(64);
const OTHER = 'sha256:' + 'b'.repeat(64);

const cases = [
  {
    name: 'annotation directly above imageDigest',
    yaml: `redis:\n  image: reg.mini.dev/redis\n  # renovate: datasource=docker depName=reg.mini.dev/redis\n  imageDigest: "${DIGEST}"\n`,
    expect: { depName: 'reg.mini.dev/redis', currentDigest: DIGEST, currentValue: undefined },
  },
  {
    name: 'imageVersion line between annotation and imageDigest',
    yaml: `mariadb:\n  image: reg.mini.dev/mariadb\n  # renovate: datasource=docker depName=reg.mini.dev/mariadb currentValue=10.6\n  imageVersion: "10.6"\n  imageDigest: "${DIGEST}"\n`,
    expect: { depName: 'reg.mini.dev/mariadb', currentDigest: DIGEST, currentValue: '10.6' },
  },
  {
    name: 'prose comment block between annotation and imageDigest',
    yaml:
      `nextcloud:\n  image: nextcloud\n  imageVersion: "latest"\n` +
      `  # renovate: datasource=docker depName=nextcloud\n` +
      `  # 2026-06-05: 92da6b0a (33.0.3) -> 4c8bf914 (33.0.5).\n` +
      `  # App patch + Debian base refresh against the Trivy CVE wave.\n` +
      `  imageDigest: "${DIGEST}"\n`,
    expect: { depName: 'nextcloud', currentDigest: DIGEST, currentValue: undefined },
  },
  {
    name: 'versioning= is captured',
    yaml: `x:\n  # renovate: datasource=docker depName=foo/bar currentValue=1.2 versioning=semver\n  imageDigest: "${DIGEST}"\n`,
    expect: { depName: 'foo/bar', currentDigest: DIGEST, currentValue: '1.2', versioning: 'semver' },
  },
  {
    name: 'unquoted digest',
    yaml: `x:\n  # renovate: datasource=docker depName=foo/bar\n  imageDigest: ${DIGEST}\n`,
    expect: { depName: 'foo/bar', currentDigest: DIGEST },
  },
];

// The annotation must NOT be able to reach across an unrelated key into the
// next image's digest — that would bump the wrong image.
const negatives = [
  {
    name: 'does not bind across an unrelated key',
    yaml:
      `a:\n  # renovate: datasource=docker depName=first/image\n  port: 6379\n` +
      `b:\n  imageDigest: "${OTHER}"\n`,
  },
  {
    name: 'does not bind across a following image: key',
    yaml:
      `a:\n  # renovate: datasource=docker depName=first/image\n` +
      `  image: second/image\n  imageDigest: "${OTHER}"\n`,
  },
];

let failed = 0;

for (const c of cases) {
  re.lastIndex = 0;
  const m = re.exec(c.yaml);
  if (!m) {
    console.error(`FAIL [${c.name}]: no match`);
    failed++;
    continue;
  }
  for (const [key, want] of Object.entries(c.expect)) {
    const got = m.groups[key];
    if (got !== want) {
      console.error(`FAIL [${c.name}]: ${key} = ${JSON.stringify(got)}, want ${JSON.stringify(want)}`);
      failed++;
    }
  }
  if (!failed) console.log(`ok   ${c.name}`);
}

for (const c of negatives) {
  re.lastIndex = 0;
  const m = re.exec(c.yaml);
  if (m) {
    console.error(`FAIL [${c.name}]: matched depName=${m.groups.depName} digest=${m.groups.currentDigest}`);
    failed++;
  } else {
    console.log(`ok   ${c.name}`);
  }
}

if (failed) {
  console.error(`\n${failed} assertion(s) failed`);
  process.exit(1);
}
console.log('\nall Schema-A assertions passed');
