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

// --- Schema D: CloudNativePG spec.imageName ------------------------------
// The built-in kubernetes manager parses manifests/ but only looks at
// container `image:` keys, so a CNPG Cluster's Postgres image is invisible
// to it. cluster-baseline's auth Postgres sat two months unbumped that way.

const schemaD = config.customManagers.find((m) =>
  m.matchStrings?.some((s) => s.includes('imageName')),
);
if (!schemaD) {
  console.error('FAIL: no customManager matching imageName found in default.json');
  process.exit(1);
}
const reD = new RegExp(schemaD.matchStrings[0], 'g');

const dCases = [
  {
    name: 'CNPG imageName, unquoted',
    yaml: `spec:\n  instances: 1\n  imageName: ghcr.io/cloudnative-pg/postgresql:18-standard-trixie@${DIGEST}\n`,
    expect: {
      depName: 'ghcr.io/cloudnative-pg/postgresql',
      currentValue: '18-standard-trixie',
      currentDigest: DIGEST,
    },
  },
  {
    name: 'CNPG imageName, quoted',
    yaml: `spec:\n  imageName: "ghcr.io/cloudnative-pg/postgresql:18@${DIGEST}"\n`,
    expect: {
      depName: 'ghcr.io/cloudnative-pg/postgresql',
      currentValue: '18',
      currentDigest: DIGEST,
    },
  },
];

for (const c of dCases) {
  reD.lastIndex = 0;
  const m = reD.exec(c.yaml);
  if (!m) {
    console.error(`FAIL [${c.name}]: no match`);
    failed++;
    continue;
  }
  let bad = false;
  for (const [key, want] of Object.entries(c.expect)) {
    if (m.groups[key] !== want) {
      console.error(`FAIL [${c.name}]: ${key} = ${JSON.stringify(m.groups[key])}, want ${JSON.stringify(want)}`);
      failed++;
      bad = true;
    }
  }
  if (!bad) console.log(`ok   ${c.name}`);
}

// A tag-only imageName has no digest to track — F-006 requires the digest, so
// not matching is the correct behaviour, not a miss.
reD.lastIndex = 0;
if (reD.exec('  imageName: ghcr.io/cloudnative-pg/postgresql:18\n')) {
  console.error('FAIL [CNPG imageName without digest]: should not match');
  failed++;
} else {
  console.log('ok   CNPG imageName without digest is not matched');
}

// --- Stateful-store packageRule ------------------------------------------
// Renovate reads `matchPackageNames` entries wrapped in slashes as regexes.
// A pattern that silently matches nothing is the same class of bug as the
// Schema-A adjacency miss, so pin it against the depNames the fleet actually
// uses (kubecloud#40 proposed reg.mini.dev/mariadb 10.6 -> v10.11 as a
// minor, which the automerge rule would have shipped to a live database).

const dbRule = config.packageRules.find(
  (r) => r.description?.startsWith('Stateful data stores'),
);
if (!dbRule) {
  console.error('FAIL: stateful-store packageRule missing from default.json');
  process.exit(1);
}
const dbPatterns = dbRule.matchPackageNames.map(
  (p) => new RegExp(p.replace(/^\/|\/$/g, '')),
);
const matchesDbRule = (dep) => dbPatterns.some((re) => re.test(dep));

const shouldMatch = [
  'reg.mini.dev/mariadb',
  'reg.mini.dev/redis',
  'ghcr.io/cloudnative-pg/postgresql',
  'keinos/sqlite3',
  'postgres',
  'mongo',
];
const shouldNotMatch = [
  'nextcloud',
  'alpine/kubectl',
  'alpine/k8s',
  'busybox',
  'rclone/rclone',
  'litestream/litestream',
  // guards against a bare-substring pattern: these are not data stores
  'my-postgres-exporter',
  'redis-operator',
];

for (const dep of shouldMatch) {
  if (matchesDbRule(dep)) console.log(`ok   stateful rule matches ${dep}`);
  else {
    console.error(`FAIL: stateful rule should match ${dep}`);
    failed++;
  }
}
for (const dep of shouldNotMatch) {
  if (!matchesDbRule(dep)) console.log(`ok   stateful rule ignores ${dep}`);
  else {
    console.error(`FAIL: stateful rule should NOT match ${dep}`);
    failed++;
  }
}


// --- kubectl skew packageRule -------------------------------------------
// kubectl is only supported within one minor of the API server, which Renovate
// cannot know. Same pattern-matching risk as the stateful rule: assert against
// the image names the fleet really uses.

const kubectlRule = config.packageRules.find((r) =>
  r.description?.startsWith('kubectl-bearing images'),
);
if (!kubectlRule) {
  console.error('FAIL: kubectl packageRule missing from default.json');
  process.exit(1);
}
const kubectlPatterns = kubectlRule.matchPackageNames.map(
  (p) => new RegExp(p.replace(/^\/|\/$/g, '')),
);
const matchesKubectlRule = (dep) => kubectlPatterns.some((re) => re.test(dep));

for (const dep of ['alpine/k8s', 'alpine/kubectl', 'bitnami/kubectl', 'rancher/kubectl']) {
  if (matchesKubectlRule(dep)) console.log(`ok   kubectl rule matches ${dep}`);
  else {
    console.error(`FAIL: kubectl rule should match ${dep}`);
    failed++;
  }
}
for (const dep of ['nextcloud', 'busybox', 'reg.mini.dev/redis', 'alpine/helm']) {
  if (!matchesKubectlRule(dep)) console.log(`ok   kubectl rule ignores ${dep}`);
  else {
    console.error(`FAIL: kubectl rule should NOT match ${dep}`);
    failed++;
  }
}

if (failed) {
  console.error(`\n${failed} assertion(s) failed`);
  process.exit(1);
}
console.log('\nall assertions passed');
