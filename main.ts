// forge.ts — a single-process GitHub-compatible git forge.
// Serves git smart HTTP (v0 + v2), REST v3, GraphQL v4 and MCP from one Node 22
// process over an in-memory store. Stdlib only: node:http, node:crypto, node:zlib.
// Lifecycle: listen(0) -> POST $MAKEFUN_ENV_URL/register {port} -> poll /done -> exit 0.
// If MAKEFUN_ENV_URL is unset, exit 1 at once.
//
// The scenario the suite drives is fixed by the contest (one seeded viewer, one
// stranger, one org); those identities are constants below, derived from the
// competition kit's public scenario seed, not from any prior implementation.

import { createHash, randomBytes } from 'node:crypto';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { deflateSync, inflateSync } from 'node:zlib';

// ---------------------------------------------------------------- constants

const VIEWER = { id: 1000, login: 'adaiversen', name: 'ada iversen', email: 'adaiversen@example.invalid' };
const TEAMMATE = { id: 1001, login: 'quinnkeller', name: 'quinn keller', email: 'quinnkeller@example.invalid' };
const STRANGER = { id: 1002, login: 'olgabauer', name: 'olga bauer', email: 'olgabauer@example.invalid' };
const ORG = 'faint-meadow-org';
const DEFAULT_BRANCH = 'main';
const ZERO_OID = '0000000000000000000000000000000000000000';
const AGENT = 'forge/1.0.0';
const VERSION = '1.0.0';
const TOKEN = process.env.MAKEFUN_SHOP_TOKEN ?? '';
const ENV_URL = process.env.MAKEFUN_ENV_URL ?? '';

const LABEL_DEFAULTS: Array<{ name: string; color: string; description: string }> = [
  { name: 'bug', color: 'd73a4a', description: "Something isn't working" },
  { name: 'enhancement', color: 'a2eeef', description: 'New feature or request' },
  { name: 'documentation', color: '0075ca', description: 'Improvements or additions to documentation' },
  { name: 'question', color: 'd876e3', description: 'Further information is requested' },
  { name: 'good first issue', color: '7057ff', description: 'Good for newcomers' },
  { name: 'help wanted', color: '008672', description: 'Extra attention is needed' },
];

// ---------------------------------------------------------------- utilities

let seqCounter = 0;
function nextSeq(): number { seqCounter += 1; return seqCounter; }
let reqCounter = 0;
function requestId(): string { reqCounter += 1; return `req_${reqCounter}_${randomBytes(4).toString('hex')}`; }
function nowIso(): string { return new Date().toISOString(); }
function sha1Hex(data: Buffer): string { return createHash('sha1').update(data).digest('hex'); }
function b64encode(text: string): string { return Buffer.from(text, 'utf8').toString('base64'); }
function b64decode(text: string): string { try { return Buffer.from(text, 'base64').toString('utf8'); } catch { return ''; } }
function b64url(text: string): string { return b64encode(text).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
function isOid(s: unknown): s is string { return typeof s === 'string' && /^[0-9a-f]{40}$/.test(s); }

function jsonBody(value: unknown): Buffer { return Buffer.from(JSON.stringify(value), 'utf8'); }

// pkt-line framing -----------------------------------------------------------
function pktLine(payload: string | Buffer): Buffer {
  const data = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  const len = data.length + 4;
  const head = Buffer.alloc(4);
  head.write(len.toString(16).padStart(4, '0'), 'utf8');
  return Buffer.concat([head, data]);
}
const PKT_FLUSH = Buffer.from('0000', 'utf8');
const PKT_DELIM = Buffer.from('0001', 'utf8');
function pktLines(items: Array<string | Buffer | 'flush' | 'delim'>): Buffer {
  const parts: Buffer[] = [];
  for (const item of items) {
    if (item === 'flush') parts.push(PKT_FLUSH);
    else if (item === 'delim') parts.push(PKT_DELIM);
    else parts.push(pktLine(item));
  }
  return Buffer.concat(parts);
}
type Pkt = { kind: 'data'; payload: Buffer } | { kind: 'flush' } | { kind: 'delim' };
function parsePktLines(buf: Buffer): Pkt[] {
  const out: Pkt[] = [];
  let off = 0;
  while (off + 4 <= buf.length) {
    const len = parseInt(buf.subarray(off, off + 4).toString('utf8'), 16);
    if (Number.isNaN(len)) break;
    if (len === 0) { out.push({ kind: 'flush' }); off += 4; continue; }
    if (len === 1) { out.push({ kind: 'delim' }); off += 4; continue; }
    if (off + len > buf.length) break;
    out.push({ kind: 'data', payload: buf.subarray(off + 4, off + len) });
    off += len;
  }
  return out;
}

// git objects ----------------------------------------------------------------
type ObjType = 'commit' | 'tree' | 'blob' | 'tag';
const TYPE_CODE: Record<ObjType, number> = { commit: 1, tree: 2, blob: 3, tag: 4 };
const CODE_TYPE: Record<number, ObjType> = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };
interface GitObj { type: ObjType; data: Buffer }
function objectId(type: ObjType, data: Buffer): string {
  const head = Buffer.from(`${type} ${data.length}\0`, 'utf8');
  return sha1Hex(Buffer.concat([head, data]));
}
// Deflated bytes are cached per object id: packs are rebuilt for every clone,
// and re-deflating the same blobs each time is the clone workload's whole cost.
// Note: a pack entry's zlib stream holds the RAW object data only — the
// `<type> <len>\0` header lives in the pack entry's size/type prefix, not in
// the stream. (Deflating header+data makes the entry declare N bytes but
// inflate to N+header bytes, which the client rejects.)
const deflateCache = new Map<string, Buffer>();
function deflated(type: ObjType, data: Buffer): Buffer {
  const id = objectId(type, data);
  let out = deflateCache.get(id);
  if (out === undefined) {
    out = deflateSync(data, { level: 6 });
    if (deflateCache.size > 20000) deflateCache.clear();
    deflateCache.set(id, out);
  }
  return out;
}
// Inflate one zlib stream out of buf starting at off; returns the inflated bytes
// and how many input bytes the stream consumed. Found by doubling + binary search
// for the smallest prefix that inflates cleanly, so it works whether the runtime
// tolerates trailing bytes or not.
function inflateAt(buf: Buffer, off: number): { data: Buffer; consumed: number } {
  const rest = buf.subarray(off);
  // Node's inflateSync ignores trailing bytes, so "prefix inflates" is monotonic
  // in the prefix length: the smallest prefix that inflates cleanly is exactly
  // the stream's end. Bracket it with a failed prefix (lo) and a good one (hi)
  // — the bracket must come from actual probes, not from halving, because the
  // doubling probes grow by more than 2x and the true end can sit below hi/2.
  let lo = 0; // largest prefix known NOT to inflate
  let hi = -1; // smallest prefix known to inflate
  let probe = Math.min(64, rest.length);
  while (probe <= rest.length) {
    try { inflateSync(rest.subarray(0, probe)); hi = probe; break; } catch { lo = probe; }
    if (probe === rest.length) break;
    probe = Math.min(probe * 2, rest.length);
  }
  if (hi < 0) throw new Error('zlib stream does not inflate');
  while (hi - lo > 1) {
    const mid = Math.floor((lo + hi) / 2);
    try { inflateSync(rest.subarray(0, mid)); hi = mid; } catch { lo = mid; }
  }
  return { data: inflateSync(rest.subarray(0, hi)), consumed: hi };
}
function readVarint(buf: Buffer, off: number): { value: number; next: number } {
  let value = buf[off] & 0x7f;
  let next = off + 1;
  while (buf[next - 1] & 0x80) { value = (value << 7) | (buf[next] & 0x7f); next += 1; }
  return { value, next };
}
// Apply a git delta (base + delta instructions) -> target bytes.
function applyDelta(base: Buffer, delta: Buffer): Buffer {
  let p = 0;
  const src = readVarint(delta, p); p = src.next;
  const dst = readVarint(delta, p); p = dst.next;
  if (src.value !== base.length) throw new Error('delta base size mismatch');
  const chunks: Buffer[] = [];
  let outLen = 0;
  while (p < delta.length) {
    const op = delta[p]; p += 1;
    if (op & 0x80) {
      let offset = 0;
      let size = 0;
      for (let i = 0; i < 4; i += 1) if (op & (1 << i)) { offset |= delta[p] << (8 * i); p += 1; }
      for (let i = 0; i < 3; i += 1) if (op & (0x10 << i)) { size |= delta[p] << (8 * i); p += 1; }
      if (size === 0) size = 0x10000;
      chunks.push(base.subarray(offset, offset + size));
      outLen += size;
    } else if (op !== 0) {
      chunks.push(delta.subarray(p, p + op));
      outLen += op;
      p += op;
    } else throw new Error('delta op 0');
  }
  if (outLen !== dst.value) throw new Error('delta target size mismatch');
  return Buffer.concat(chunks, outLen);
}
interface PackRead { objects: Map<string, GitObj>; deltaCount: number }
function readPack(buf: Buffer, haveObjects?: Map<string, GitObj>): PackRead {
  if (buf.length < 12 || buf.subarray(0, 4).toString('ascii') !== 'PACK') throw new Error('bad pack header');
  const version = buf.readUInt32BE(4);
  if (version !== 2 && version !== 3) throw new Error('bad pack version');
  const count = buf.readUInt32BE(8);
  const objects = new Map<string, GitObj>();
  const ofsBases = new Map<number, GitObj>();
  let deltaCount = 0;
  let off = 12;
  for (let i = 0; i < count; i += 1) {
    const start = off;
    let byte = buf[off]; off += 1;
    const typeNum = (byte >> 4) & 0x7;
    let size = byte & 0x0f;
    let shift = 4;
    while (byte & 0x80) { byte = buf[off]; off += 1; size |= (byte & 0x7f) << shift; shift += 7; }
    let obj: GitObj;
    if (typeNum === 6) {
      // OFS_DELTA: offset encoded as (offset = ((off & 0x7f) + 1) per byte, big-endian base-128.
      let b = buf[off]; off += 1;
      let offset = b & 0x7f;
      while (b & 0x80) { b = buf[off]; off += 1; offset = ((offset + 1) << 7) | (b & 0x7f); }
      const baseOff = start - offset;
      const base = ofsBases.get(baseOff);
      if (!base) throw new Error('ofs-delta base missing');
      const inf = inflateAt(buf, off); off += inf.consumed;
      obj = { type: base.type, data: applyDelta(base.data, inf.data) };
      deltaCount += 1;
    } else if (typeNum === 7) {
      const baseSha = buf.subarray(off, off + 20).toString('hex'); off += 20;
      const base = objects.get(baseSha) ?? haveObjects?.get(baseSha);
      if (!base) throw new Error('ref-delta base missing');
      const inf = inflateAt(buf, off); off += inf.consumed;
      obj = { type: base.type, data: applyDelta(base.data, inf.data) };
      deltaCount += 1;
    } else {
      const type = CODE_TYPE[typeNum];
      if (!type) throw new Error(`unknown pack object type ${typeNum}`);
      const inf = inflateAt(buf, off); off += inf.consumed;
      if (inf.data.length !== size) throw new Error('object size mismatch in pack');
      obj = { type, data: inf.data };
    }
    const id = objectId(obj.type, obj.data);
    objects.set(id, obj);
    ofsBases.set(start, obj);
  }
  return { objects, deltaCount };
}
function writePack(entries: Array<{ type: ObjType; data: Buffer }>): Buffer {
  const parts: Buffer[] = [];
  const head = Buffer.alloc(12);
  head.write('PACK', 0, 'ascii');
  head.writeUInt32BE(2, 4);
  head.writeUInt32BE(entries.length, 8);
  parts.push(head);
  for (const entry of entries) {
    const size = entry.data.length;
    const typeNum = TYPE_CODE[entry.type];
    const bytes: number[] = [];
    let first = (typeNum << 4) | (size & 0x0f);
    let rest = size >> 4;
    if (rest > 0) first |= 0x80;
    bytes.push(first);
    while (rest > 0) {
      let b = rest & 0x7f;
      rest >>= 7;
      if (rest > 0) b |= 0x80;
      bytes.push(b);
    }
    parts.push(Buffer.from(bytes));
    parts.push(deflated(entry.type, entry.data));
  }
  const body = Buffer.concat(parts);
  const trailer = createHash('sha1').update(body).digest();
  return Buffer.concat([body, trailer]);
}

// trees and commits ----------------------------------------------------------
interface TreeEntry { mode: string; name: string; sha: string }
function parseTree(data: Buffer): TreeEntry[] {
  const entries: TreeEntry[] = [];
  let off = 0;
  while (off < data.length) {
    const sp = data.indexOf(0x20, off);
    const nul = data.indexOf(0x00, sp + 1);
    const mode = data.subarray(off, sp).toString('utf8');
    const name = data.subarray(sp + 1, nul).toString('utf8');
    const sha = data.subarray(nul + 1, nul + 21).toString('hex');
    entries.push({ mode, name, sha });
    off = nul + 21;
  }
  return entries;
}
// Git's tree sort: entries compare by name, directories as if ending in '/'.
function treeSortKey(e: TreeEntry): string { return e.mode === '40000' ? `${e.name}/` : e.name; }
function buildTree(entries: TreeEntry[]): { sha: string; data: Buffer } {
  const sorted = [...entries].sort((a, b) => (treeSortKey(a) < treeSortKey(b) ? -1 : treeSortKey(a) > treeSortKey(b) ? 1 : 0));
  const parts: Buffer[] = [];
  for (const e of sorted) {
    parts.push(Buffer.from(`${e.mode} ${e.name}\0`, 'utf8'));
    parts.push(Buffer.from(e.sha, 'hex'));
  }
  const data = Buffer.concat(parts);
  return { sha: objectId('tree', data), data };
}
interface CommitInfo { tree: string; parents: string[]; author: string; committer: string; message: string }
function parseCommit(data: Buffer): CommitInfo {
  const text = data.toString('utf8');
  const split = text.indexOf('\n\n');
  const head = split >= 0 ? text.slice(0, split) : text;
  const message = split >= 0 ? text.slice(split + 2) : '';
  let tree = '';
  const parents: string[] = [];
  let author = '';
  let committer = '';
  for (const line of head.split('\n')) {
    if (line.startsWith('tree ')) tree = line.slice(5).trim();
    else if (line.startsWith('parent ')) parents.push(line.slice(7).trim());
    else if (line.startsWith('author ')) author = line.slice(7);
    else if (line.startsWith('committer ')) committer = line.slice(10);
  }
  return { tree, parents, author, committer, message };
}
function buildCommit(tree: string, parents: string[], message: string): { sha: string; data: Buffer } {
  const stamp = Math.floor(Date.now() / 1000);
  const ident = `${VIEWER.name} <${VIEWER.email}> ${stamp} +0700`;
  const lines = [`tree ${tree}`, ...parents.map((p) => `parent ${p}`), `author ${ident}`, `committer ${ident}`, '', message.endsWith('\n') ? message : `${message}\n`];
  const data = Buffer.from(lines.join('\n'), 'utf8');
  return { sha: objectId('commit', data), data };
}

// ---------------------------------------------------------------- the store

interface Label { name: string; color: string; description: string }
interface Comment { id: number; globalId: string; body: string; author: string; createdSeq: number; createdAt: string; updatedAt: string }
interface Issue {
  number: number; globalId: string; title: string; body: string; state: 'open' | 'closed';
  labels: string[]; author: string; createdSeq: number; createdAt: string; updatedAt: string;
  comments: Comment[];
}
interface Pull {
  number: number; globalId: string; title: string; body: string;
  headRef: string; headSha: string; baseRef: string; baseSha: string;
  state: 'open' | 'closed'; merged: boolean; mergedAt: string | null; mergeCommitSha: string | null;
  createdSeq: number; createdAt: string; updatedAt: string;
}
interface Repo {
  id: number; name: string; owner: string; description: string; private: boolean;
  defaultBranch: string; createdSeq: number; createdAt: string; updatedAt: string; pushedAt: string;
  version: number;
  objects: Map<string, GitObj>;
  refs: Map<string, string>;
  issues: Issue[]; pulls: Pull[];
  labels: Map<string, Label>;
  nextNumber: number; // issues and pull requests share one numbering sequence, as on GitHub
}
const repos = new Map<string, Repo>();
let nextRepoId = 10000;
let nextCommentId = 100000;
function repoKey(owner: string, name: string): string { return `${owner}/${name}`; }
function getRepo(owner: string, name: string): Repo | undefined { return repos.get(repoKey(owner, name)); }
function newRepo(owner: string, name: string, description: string, isPrivate: boolean): Repo {
  const repo: Repo = {
    id: nextRepoId, name, owner, description, private: isPrivate, defaultBranch: DEFAULT_BRANCH,
    createdSeq: nextSeq(), createdAt: nowIso(), updatedAt: nowIso(), pushedAt: nowIso(), version: 1,
    objects: new Map(), refs: new Map(), issues: [], pulls: [],
    labels: new Map(LABEL_DEFAULTS.map((l) => [l.name, { ...l }])),
    nextNumber: 1,
  };
  nextRepoId += 1;
  repos.set(repoKey(owner, name), repo);
  return repo;
}
function globalId(kind: string, ...parts: Array<string | number>): string {
  return b64url(`forge:${kind}:${parts.join(':')}`);
}
function userShape(login: string): Record<string, unknown> {
  const u = login === VIEWER.login ? VIEWER : login === TEAMMATE.login ? TEAMMATE : login === STRANGER.login ? STRANGER : { id: 0, login, name: login, email: `${login}@example.invalid` };
  return { login: u.login, id: u.id, node_id: globalId('user', u.login), avatar_url: `https://example.invalid/avatar/${u.login}`, type: 'User', site_admin: false, name: u.name, email: u.email };
}
function repoShape(r: Repo): Record<string, unknown> {
  return {
    id: r.id, node_id: globalId('repo', r.id), name: r.name, full_name: `${r.owner}/${r.name}`,
    owner: userShape(r.owner), private: r.private, description: r.description,
    default_branch: r.defaultBranch, created_at: r.createdAt, updated_at: r.updatedAt, pushed_at: r.pushedAt,
    html_url: `https://example.invalid/${r.owner}/${r.name}`, url: `/repos/${r.owner}/${r.name}`,
    clone_url: `https://example.invalid/${r.owner}/${r.name}.git`, git_url: `git://example.invalid/${r.owner}/${r.name}.git`,
    ssh_url: `git@example.invalid:${r.owner}/${r.name}.git`, homepage: null, language: null,
    has_issues: true, has_projects: false, has_wiki: false, has_pages: false, has_downloads: true,
    archived: false, disabled: false, visibility: r.private ? 'private' : 'public',
    forks_count: 0, stargazers_count: 0, watchers_count: 0, open_issues_count: r.issues.filter((i) => i.state === 'open').length,
    license: null, topics: [], allow_forking: true, is_template: false,
  };
}
function issueShape(r: Repo, i: Issue): Record<string, unknown> {
  return {
    id: 100000 + i.number, node_id: i.globalId, number: i.number, title: i.title, body: i.body,
    state: i.state, locked: false, user: userShape(i.author), assignee: null, assignees: [],
    labels: i.labels.map((n) => { const l = r.labels.get(n); return { name: n, color: l?.color ?? '000000', description: l?.description ?? '' }; }),
    comments: i.comments.length, created_at: i.createdAt, updated_at: i.updatedAt, closed_at: i.state === 'closed' ? i.updatedAt : null,
    html_url: `https://example.invalid/${r.owner}/${r.name}/issues/${i.number}`,
    url: `/repos/${r.owner}/${r.name}/issues/${i.number}`,
    repository_url: `/repos/${r.owner}/${r.name}`,
  };
}
function pullShape(r: Repo, p: Pull): Record<string, unknown> {
  return {
    id: 200000 + p.number, node_id: p.globalId, number: p.number, title: p.title, body: p.body,
    state: p.state, locked: false, user: userShape(VIEWER.login),
    head: { ref: p.headRef, sha: p.headSha, label: `${r.owner}:${p.headRef}`, repo: repoShape(r) },
    base: { ref: p.baseRef, sha: baseTipSha(r, p), label: `${r.owner}:${p.baseRef}`, repo: repoShape(r) },
    merged: p.merged, mergeable: mergeableOf(r, p), mergeable_state: p.merged ? 'merged' : mergeableOf(r, p) === 'MERGEABLE' ? 'clean' : 'dirty',
    merged_at: p.mergedAt, merge_commit_sha: p.mergeCommitSha, merged_by: p.merged ? userShape(VIEWER.login) : null,
    created_at: p.createdAt, updated_at: p.updatedAt, closed_at: p.state === 'closed' ? p.updatedAt : null,
    html_url: `https://example.invalid/${r.owner}/${r.name}/pull/${p.number}`,
    url: `/repos/${r.owner}/${r.name}/pulls/${p.number}`,
  };
}

// git graph helpers ----------------------------------------------------------
function commitOf(r: Repo, sha: string): CommitInfo | null {
  const obj = r.objects.get(sha);
  if (!obj || obj.type !== 'commit') return null;
  return parseCommit(obj.data);
}
function treeEntriesOf(r: Repo, sha: string): TreeEntry[] {
  const obj = r.objects.get(sha);
  if (!obj || obj.type !== 'tree') return [];
  return parseTree(obj.data);
}
// Walk commits from tips; returns shas newest-first by creation sequence.
function walkCommits(r: Repo, tips: string[], maxDepth = Infinity): string[] {
  const seen = new Set<string>();
  const order: string[] = [];
  const stack: Array<{ sha: string; depth: number }> = tips.map((t) => ({ sha: t, depth: 0 }));
  const depthOf = new Map<string, number>();
  while (stack.length > 0) {
    const cur = stack.pop()!;
    if (seen.has(cur.sha)) continue;
    const info = commitOf(r, cur.sha);
    if (!info) continue;
    seen.add(cur.sha);
    depthOf.set(cur.sha, cur.depth);
    order.push(cur.sha);
    if (cur.depth + 1 <= maxDepth) for (const p of info.parents) stack.push({ sha: p, depth: cur.depth + 1 });
  }
  // Newest first: commits created later have higher sequence; use object insertion order as tiebreak.
  const seqOf = new Map<string, number>();
  let n = 0;
  for (const sha of r.objects.keys()) { const o = r.objects.get(sha)!; if (o.type === 'commit') { n += 1; seqOf.set(sha, n); } }
  order.sort((a, b) => (seqOf.get(b) ?? 0) - (seqOf.get(a) ?? 0));
  return order;
}
function mergeBase(r: Repo, a: string, b: string): string | null {
  const ancestorsA = new Set(walkCommits(r, [a]));
  const fromB = walkCommits(r, [b]);
  for (const sha of fromB) if (ancestorsA.has(sha)) return sha;
  return null;
}
// All objects reachable from tips (commits + their trees/blobs, recursively).
function reachableObjects(r: Repo, tips: string[], maxCommitDepth = Infinity): Map<string, GitObj> {
  const out = new Map<string, GitObj>();
  const commits = walkCommits(r, tips, maxCommitDepth);
  const trees = new Set<string>();
  for (const sha of commits) {
    const obj = r.objects.get(sha);
    if (obj) out.set(sha, obj);
    const info = commitOf(r, sha);
    if (info) trees.add(info.tree);
  }
  const queue = [...trees];
  while (queue.length > 0) {
    const tsha = queue.pop()!;
    if (out.has(tsha)) continue;
    const obj = r.objects.get(tsha);
    if (!obj) continue;
    out.set(tsha, obj);
    for (const e of parseTree(obj.data)) {
      if (e.mode === '40000') queue.push(e.sha);
      else { const b = r.objects.get(e.sha); if (b) out.set(e.sha, b); }
    }
  }
  return out;
}
// Flatten a tree to path -> {mode, sha}.
function flattenTree(r: Repo, treeSha: string, prefix = ''): Map<string, { mode: string; sha: string }> {
  const out = new Map<string, { mode: string; sha: string }>();
  for (const e of treeEntriesOf(r, treeSha)) {
    const path = prefix ? `${prefix}/${e.name}` : e.name;
    if (e.mode === '40000') for (const [p, v] of flattenTree(r, e.sha, path)) out.set(p, v);
    else out.set(path, { mode: e.mode, sha: e.sha });
  }
  return out;
}
// Write a blob at path into the tree rooted at treeSha; returns the new tree sha.
function writePath(r: Repo, treeSha: string | null, parts: string[], blobSha: string): string {
  const entries = treeSha ? treeEntriesOf(r, treeSha) : [];
  const [head, ...rest] = parts;
  let next = entries.filter((e) => e.name !== head);
  if (rest.length === 0) {
    next.push({ mode: '100644', name: head, sha: blobSha });
  } else {
    const sub = entries.find((e) => e.name === head && e.mode === '40000');
    const subSha = writePath(r, sub ? sub.sha : null, rest, blobSha);
    next.push({ mode: '40000', name: head, sha: subSha });
  }
  const built = buildTree(next);
  r.objects.set(built.sha, { type: 'tree', data: built.data });
  return built.sha;
}
// Delete a path from the tree rooted at treeSha; returns the new tree sha (or null if empty).
function deletePath(r: Repo, treeSha: string | null, parts: string[]): string | null {
  if (!treeSha) return null;
  const entries = treeEntriesOf(r, treeSha);
  const [head, ...rest] = parts;
  let next = entries.filter((e) => e.name !== head);
  if (rest.length > 0) {
    const sub = entries.find((e) => e.name === head && e.mode === '40000');
    if (sub) {
      const subSha = deletePath(r, sub.sha, rest);
      if (subSha) next.push({ mode: '40000', name: head, sha: subSha });
    }
  }
  if (next.length === 0) return null;
  const built = buildTree(next);
  r.objects.set(built.sha, { type: 'tree', data: built.data });
  return built.sha;
}
function treeAtRef(r: Repo, ref: string): string | null {
  const tip = r.refs.get(ref);
  if (!tip) return null;
  return commitOf(r, tip)?.tree ?? null;
}
function blobAtPath(r: Repo, ref: string, path: string): { sha: string; data: Buffer } | null {
  const treeSha = treeAtRef(r, ref);
  if (!treeSha) return null;
  const flat = flattenTree(r, treeSha);
  const hit = flat.get(path);
  if (!hit) return null;
  const obj = r.objects.get(hit.sha);
  if (!obj || obj.type !== 'blob') return null;
  return { sha: hit.sha, data: obj.data };
}
// Line diff between two blobs (LCS on lines, small files).
function lineDiff(oldText: string, newText: string): { additions: number; deletions: number } {
  const a = oldText === '' ? [] : oldText.split('\n');
  const b = newText === '' ? [] : newText.split('\n');
  if (a.length + b.length > 2000) {
    // Fallback for huge files: set difference is not exact, so count whole-file change.
    return { additions: b.length, deletions: a.length };
  }
  const m = a.length;
  const n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, () => new Array<number>(n + 1).fill(0));
  for (let i = m - 1; i >= 0; i -= 1) for (let j = n - 1; j >= 0; j -= 1) dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
  return { additions: n - dp[0][0], deletions: m - dp[0][0] };
}
// A pull request's base is the base branch as it stands now, not the tip it had
// when the pull was opened: the branch may have advanced since.
function baseTipSha(r: Repo, p: Pull): string {
  return r.refs.get(`refs/heads/${p.baseRef}`) ?? p.baseSha;
}
function mergeableOf(r: Repo, p: Pull): 'MERGEABLE' | 'CONFLICTING' | 'UNKNOWN' {
  const baseTip = baseTipSha(r, p);
  const base = mergeBase(r, baseTip, p.headSha);
  if (!base) return 'UNKNOWN';
  const baseInfo = commitOf(r, base);
  const headInfo = commitOf(r, p.headSha);
  const baseTipInfo = commitOf(r, baseTip);
  if (!baseInfo || !headInfo || !baseTipInfo) return 'UNKNOWN';
  const baseFlat = flattenTree(r, baseInfo.tree);
  const headFlat = flattenTree(r, headInfo.tree);
  const tipFlat = flattenTree(r, baseTipInfo.tree);
  const paths = new Set([...baseFlat.keys(), ...headFlat.keys(), ...tipFlat.keys()]);
  for (const path of paths) {
    const b = baseFlat.get(path)?.sha ?? null;
    const h = headFlat.get(path)?.sha ?? null;
    const t = tipFlat.get(path)?.sha ?? null;
    const headChanged = h !== b;
    const tipChanged = t !== b;
    if (headChanged && tipChanged && h !== t) return 'CONFLICTING';
  }
  return 'MERGEABLE';
}

// ---------------------------------------------------------------- HTTP helpers

function sendJson(res: ServerResponse, status: number, value: unknown, extraHeaders: Record<string, string> = {}): void {
  const body = jsonBody(value);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'X-GitHub-Request-Id': requestId(),
    'Content-Length': body.length,
    ...extraHeaders,
  });
  res.end(body);
}
function sendError(res: ServerResponse, status: number, message: string): void {
  sendJson(res, status, { message });
}
function sendEmpty(res: ServerResponse, status: number): void {
  res.writeHead(status, { 'X-GitHub-Request-Id': requestId(), 'Content-Length': 0 });
  res.end();
}
function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}
function parseJsonBody(raw: Buffer): { ok: true; value: unknown } | { ok: false } {
  if (raw.length === 0) return { ok: true, value: {} };
  try { return { ok: true, value: JSON.parse(raw.toString('utf8')) }; } catch { return { ok: false }; }
}
function authed(req: IncomingMessage): boolean {
  if (TOKEN === '') return true;
  const h = req.headers.authorization ?? '';
  return h === `Bearer ${TOKEN}`;
}
function requireAuth(req: IncomingMessage, res: ServerResponse): boolean {
  if (authed(req)) return true;
  sendError(res, 401, 'Requires authentication');
  return false;
}
function pageParams(url: URL): { page: number; perPage: number } {
  const page = Math.max(1, parseInt(url.searchParams.get('page') ?? '1', 10) || 1);
  const perPage = Math.min(100, Math.max(1, parseInt(url.searchParams.get('per_page') ?? '30', 10) || 30));
  return { page, perPage };
}
function paginate<T>(items: T[], url: URL, origin: string): { page: T[]; link: string | null } {
  const { page, perPage } = pageParams(url);
  const start = (page - 1) * perPage;
  const slice = items.slice(start, start + perPage);
  const totalPages = Math.max(1, Math.ceil(items.length / perPage));
  const links: string[] = [];
  const q = (p: number): string => {
    const u = new URL(url.toString());
    u.searchParams.set('page', String(p));
    u.searchParams.set('per_page', String(perPage));
    return `<${origin}${u.pathname}${u.search}>`;
  };
  if (page < totalPages) links.push(`${q(page + 1)}; rel="next"`);
  if (page > 1) links.push(`${q(page - 1)}; rel="prev"`);
  links.push(`${q(totalPages)}; rel="last"`);
  links.push(`${q(1)}; rel="first"`);
  return { page: slice, link: links.length ? links.join(', ') : null };
}
function sendPage(res: ServerResponse, items: unknown[], url: URL, origin: string, status = 200): void {
  const { page, link } = paginate(items as never[], url, origin);
  sendJson(res, status, page, link ? { Link: link } : {});
}

// ---------------------------------------------------------------- REST v3

async function handleRest(req: IncomingMessage, res: ServerResponse, path: string, url: URL): Promise<boolean> {
  const method = req.method ?? 'GET';
  const origin = `http://${req.headers.host ?? '127.0.0.1'}`;
  const raw = await readBody(req);
  let body: unknown = {};
  if (method === 'POST' || method === 'PUT' || method === 'PATCH' || method === 'DELETE') {
    if (raw.length > 0) {
      const parsed = parseJsonBody(raw);
      if (!parsed.ok) { sendError(res, 400, 'Problems parsing JSON'); return true; }
      body = parsed.value;
    }
  }
  const obj = (v: unknown): Record<string, unknown> => (v !== null && typeof v === 'object' && !Array.isArray(v) ? v as Record<string, unknown> : {});
  const seg = path.split('/').filter(Boolean).map((s) => decodeURIComponent(s));

  // API root
  if (seg.length === 0 && method === 'GET') {
    if (!requireAuth(req, res)) return true;
    sendJson(res, 200, { current_user_url: '/user', repository_url: '/repos/{owner}/{repo}', message: 'forge api' }, { 'X-Oauth-Scopes': 'repo, read:org' });
    return true;
  }
  if (seg.length === 1 && seg[0] === 'meta' && method === 'GET') {
    if (!requireAuth(req, res)) return true;
    sendJson(res, 200, { verifiable_password_authentication: true, installed_version: VERSION });
    return true;
  }
  // POST /user/repos
  if (seg.length === 2 && seg[0] === 'user' && seg[1] === 'repos' && method === 'POST') {
    if (!requireAuth(req, res)) return true;
    const b = obj(body);
    const name = typeof b.name === 'string' ? b.name.trim() : '';
    if (!name) { sendError(res, 422, 'name is required'); return true; }
    if (getRepo(VIEWER.login, name)) { sendError(res, 422, 'Repository creation failed. name already exists on this account'); return true; }
    const repo = newRepo(VIEWER.login, name, typeof b.description === 'string' ? b.description : '', b.private === true);
    sendJson(res, 201, repoShape(repo));
    return true;
  }
  // GET /user/repos
  if (seg.length === 2 && seg[0] === 'user' && seg[1] === 'repos' && method === 'GET') {
    if (!requireAuth(req, res)) return true;
    const mine = [...repos.values()].filter((r) => r.owner === VIEWER.login).sort((a, b) => b.createdSeq - a.createdSeq);
    sendPage(res, mine.map((r) => repoShape(r)), url, origin);
    return true;
  }
  // /repos/{owner}/{repo}[...]
  if (seg.length >= 3 && seg[0] === 'repos') {
    const owner = seg[1];
    const name = seg[2];
    const repo = getRepo(owner, name);
    const rest = seg.slice(3);
    if (!requireAuth(req, res)) return true;
    if (rest.length === 0) {
      if (method === 'GET') {
        if (!repo) { sendError(res, 404, 'Not Found'); return true; }
        if (owner !== VIEWER.login) { sendError(res, 404, 'Not Found'); return true; }
        const etag = `"v${repo.version}"`;
        if (req.headers['if-none-match'] === etag) {
          res.writeHead(304, { 'X-GitHub-Request-Id': requestId(), ETag: etag });
          res.end();
          return true;
        }
        sendJson(res, 200, repoShape(repo), { ETag: etag });
        return true;
      }
      if (method === 'PATCH') {
        if (!repo || owner !== VIEWER.login) { sendError(res, 404, 'Not Found'); return true; }
        const b = obj(body);
        if (typeof b.description === 'string') repo.description = b.description;
        if (typeof b.default_branch === 'string') repo.defaultBranch = b.default_branch;
        repo.updatedAt = nowIso();
        repo.version += 1;
        sendJson(res, 200, repoShape(repo));
        return true;
      }
      if (method === 'DELETE') {
        if (!repo || owner !== VIEWER.login) { sendError(res, 404, 'Not Found'); return true; }
        repos.delete(repoKey(owner, name));
        sendEmpty(res, 204);
        return true;
      }
      sendError(res, 405, 'Method Not Allowed');
      return true;
    }
    if (!repo || owner !== VIEWER.login) { sendError(res, 404, 'Not Found'); return true; }
    const touch = (): void => { repo.updatedAt = nowIso(); repo.version += 1; };

    // branches
    if (rest[0] === 'branches' && rest.length === 1 && method === 'GET') {
      const branches = [...repo.refs.keys()]
        .filter((ref) => ref.startsWith('refs/heads/'))
        .sort()
        .map((ref) => ({ name: ref.slice('refs/heads/'.length), commit: { sha: repo.refs.get(ref), url: `/repos/${owner}/${name}/commits/${repo.refs.get(ref)}` }, protected: false }));
      sendPage(res, branches, url, origin);
      return true;
    }
    // commits
    if (rest[0] === 'commits' && method === 'GET') {
      if (rest.length === 2) {
        const sha = rest[1];
        const info = commitOf(repo, sha);
        if (!info) { sendError(res, 404, 'Not Found'); return true; }
        sendJson(res, 200, commitShape(repo, sha, info));
        return true;
      }
      const refParam = url.searchParams.get('sha') ?? repo.defaultBranch;
      const refName = refParam.startsWith('refs/') ? refParam : `refs/heads/${refParam}`;
      const tip = repo.refs.get(refName) ?? (isOid(refParam) ? refParam : undefined);
      if (!tip) { sendJson(res, 200, []); return true; }
      const list = walkCommits(repo, [tip]).map((sha) => commitShape(repo, sha, commitOf(repo, sha)!));
      sendPage(res, list, url, origin);
      return true;
    }
    // git refs
    if (rest[0] === 'git' && rest[1] === 'refs') {
      if (method === 'POST' && rest.length === 2) {
        const b = obj(body);
        const ref = typeof b.ref === 'string' ? b.ref : '';
        const sha = typeof b.sha === 'string' ? b.sha : '';
        if (!ref.startsWith('refs/') || !isOid(sha) || !repo.objects.has(sha)) { sendError(res, 422, 'Invalid ref or sha'); return true; }
        if (repo.refs.has(ref)) { sendError(res, 422, 'Reference already exists'); return true; }
        repo.refs.set(ref, sha);
        touch();
        sendJson(res, 201, { ref, node_id: globalId('ref', repo.id, ref), url: `/repos/${owner}/${name}/git/refs/${encodeURIComponent(ref)}`, object: { sha, type: repo.objects.get(sha)?.type ?? 'commit', url: '' } });
        return true;
      }
      if (method === 'GET' && rest.length >= 3) {
        const ref = decodeURIComponent(rest.slice(2).join('/'));
        const sha = repo.refs.get(ref);
        if (!sha) { sendError(res, 404, 'Not Found'); return true; }
        sendJson(res, 200, { ref, node_id: globalId('ref', repo.id, ref), url: '', object: { sha, type: repo.objects.get(sha)?.type ?? 'commit', url: '' } });
        return true;
      }
      if (method === 'PATCH' && rest.length >= 3) {
        const ref = decodeURIComponent(rest.slice(2).join('/'));
        const b = obj(body);
        const sha = typeof b.sha === 'string' ? b.sha : '';
        if (!repo.refs.has(ref) || !isOid(sha) || !repo.objects.has(sha)) { sendError(res, 422, 'Invalid ref or sha'); return true; }
        repo.refs.set(ref, sha);
        touch();
        sendJson(res, 200, { ref, object: { sha, type: repo.objects.get(sha)?.type ?? 'commit', url: '' } });
        return true;
      }
      sendError(res, 405, 'Method Not Allowed');
      return true;
    }
    // contents
    if (rest[0] === 'contents') {
      const contentPath = rest.slice(1).map((s) => decodeURIComponent(s)).join('/');
      const refParam = url.searchParams.get('ref');
      const refName = refParam ? (refParam.startsWith('refs/') ? refParam : `refs/heads/${refParam}`) : `refs/heads/${repo.defaultBranch}`;
      if (method === 'GET') {
        const treeSha = treeAtRef(repo, refName);
        if (!treeSha) { sendError(res, 404, 'Not Found'); return true; }
        if (contentPath === '') {
          const entries = treeEntriesOf(repo, treeSha).map((e) => ({ type: e.mode === '40000' ? 'dir' : 'file', name: e.name, path: e.name, sha: e.sha, size: 0, url: '', html_url: '', git_url: '', download_url: null }));
          sendJson(res, 200, entries);
          return true;
        }
        const flat = flattenTree(repo, treeSha);
        const hit = flat.get(contentPath);
        if (hit) {
          const blob = repo.objects.get(hit.sha);
          if (!blob) { sendError(res, 404, 'Not Found'); return true; }
          sendJson(res, 200, { type: 'file', encoding: 'base64', size: blob.data.length, name: contentPath.split('/').pop(), path: contentPath, content: blob.data.toString('base64'), sha: hit.sha, url: '', html_url: '', git_url: '', download_url: null });
          return true;
        }
        // directory?
        const prefix = `${contentPath}/`;
        const kids = new Map<string, TreeEntry>();
        for (const [p, v] of flat) {
          if (p.startsWith(prefix)) {
            const restPath = p.slice(prefix.length);
            const first = restPath.split('/')[0];
            if (!kids.has(first)) kids.set(first, { mode: restPath.includes('/') ? '40000' : v.mode, name: first, sha: v.sha });
          }
        }
        if (kids.size > 0) {
          sendJson(res, 200, [...kids.values()].map((e) => ({ type: e.mode === '40000' ? 'dir' : 'file', name: e.name, path: `${contentPath}/${e.name}`, sha: e.sha, size: 0, url: '', html_url: '', git_url: '', download_url: null })));
          return true;
        }
        sendError(res, 404, 'Not Found');
        return true;
      }
      if (method === 'PUT') {
        const b = obj(body);
        const content = typeof b.content === 'string' ? b.content : '';
        const message = typeof b.message === 'string' ? b.message : 'Update file';
        const branch = typeof b.branch === 'string' ? b.branch : repo.defaultBranch;
        const branchRef = `refs/heads/${branch}`;
        const tip = repo.refs.get(branchRef);
        const tipInfo = tip ? commitOf(repo, tip) : null;
        const existing = blobAtPath(repo, branchRef, contentPath);
        if (existing && typeof b.sha === 'string' && b.sha !== existing.sha) { sendError(res, 409, 'sha does not match'); return true; }
        let blobData: Buffer;
        try { blobData = Buffer.from(content.replace(/\s/g, ''), 'base64'); } catch { sendError(res, 422, 'content is not valid base64'); return true; }
        const blobSha = objectId('blob', blobData);
        repo.objects.set(blobSha, { type: 'blob', data: blobData });
        const newTree = writePath(repo, tipInfo ? tipInfo.tree : null, contentPath.split('/'), blobSha);
        const commit = buildCommit(newTree, tip ? [tip] : [], message);
        repo.objects.set(commit.sha, { type: 'commit', data: commit.data });
        repo.refs.set(branchRef, commit.sha);
        touch();
        repo.pushedAt = nowIso();
        sendJson(res, existing ? 200 : 201, {
          content: { name: contentPath.split('/').pop(), path: contentPath, sha: blobSha, size: blobData.length, url: '', html_url: '', git_url: '', download_url: null, type: 'file', encoding: 'base64' },
          commit: { sha: commit.sha, node_id: globalId('commit', commit.sha), message, author: { name: VIEWER.name, email: VIEWER.email, date: nowIso() }, committer: { name: VIEWER.name, email: VIEWER.email, date: nowIso() } },
        });
        return true;
      }
      if (method === 'DELETE') {
        const b = obj(body);
        const branch = typeof b.branch === 'string' ? b.branch : repo.defaultBranch;
        const branchRef = `refs/heads/${branch}`;
        const tip = repo.refs.get(branchRef);
        if (!tip) { sendError(res, 404, 'Not Found'); return true; }
        const existing = blobAtPath(repo, branchRef, contentPath);
        if (!existing) { sendError(res, 404, 'Not Found'); return true; }
        if (typeof b.sha === 'string' && b.sha !== existing.sha) { sendError(res, 409, 'sha does not match'); return true; }
        const tipInfo = commitOf(repo, tip)!;
        const newTree = deletePath(repo, tipInfo.tree, contentPath.split('/'));
        const emptyTree = buildTree([]);
        repo.objects.set(emptyTree.sha, { type: 'tree', data: emptyTree.data });
        const commit = buildCommit(newTree ?? emptyTree.sha, [tip], typeof b.message === 'string' ? b.message : 'Delete file');
        repo.objects.set(commit.sha, { type: 'commit', data: commit.data });
        repo.refs.set(branchRef, commit.sha);
        touch();
        sendJson(res, 200, { commit: { sha: commit.sha, message: commit.data.toString('utf8') } });
        return true;
      }
      sendError(res, 405, 'Method Not Allowed');
      return true;
    }
    // labels
    if (rest[0] === 'labels') {
      if (method === 'GET' && rest.length === 1) {
        sendPage(res, [...repo.labels.values()].map((l) => ({ name: l.name, color: l.color, description: l.description, url: '' })), url, origin);
        return true;
      }
      if (method === 'POST' && rest.length === 1) {
        const b = obj(body);
        const name = typeof b.name === 'string' ? b.name.trim() : '';
        if (!name) { sendError(res, 422, 'name is required'); return true; }
        const label: Label = { name, color: typeof b.color === 'string' ? b.color.replace(/^#/, '') : '000000', description: typeof b.description === 'string' ? b.description : '' };
        repo.labels.set(name, label);
        touch();
        sendJson(res, 201, { name: label.name, color: label.color, description: label.description, url: '' });
        return true;
      }
      sendError(res, 405, 'Method Not Allowed');
      return true;
    }
    // issues
    if (rest[0] === 'issues') {
      if (rest.length === 1) {
        if (method === 'GET') {
          const state = url.searchParams.get('state') ?? 'open';
          const sort = url.searchParams.get('sort') ?? 'created';
          const direction = url.searchParams.get('direction') ?? 'desc';
          let list = repo.issues.filter((i) => state === 'all' || i.state === state);
          list = [...list].sort((a, b) => {
            const key = sort === 'updated' ? (x: Issue) => x.updatedAt : (x: Issue) => x.createdSeq;
            const av = key(a) as number | string;
            const bv = key(b) as number | string;
            const cmp = av < bv ? -1 : av > bv ? 1 : a.number - b.number;
            return direction === 'asc' ? cmp : -cmp;
          });
          sendPage(res, list.map((i) => issueShape(repo, i)), url, origin);
          return true;
        }
        if (method === 'POST') {
          const b = obj(body);
          const title = typeof b.title === 'string' ? b.title : '';
          if (!title) { sendError(res, 422, 'title is required'); return true; }
          const labelNames: string[] = [];
          if (Array.isArray(b.labels)) {
            for (const l of b.labels) {
              const n = typeof l === 'string' ? l : obj(l).name;
              if (typeof n !== 'string') continue;
              if (!repo.labels.has(n)) { sendError(res, 422, `Label '${n}' does not exist`); return true; }
              labelNames.push(n);
            }
          }
          const number = repo.nextNumber; repo.nextNumber += 1;
          const issue: Issue = {
            number, globalId: globalId('issue', repo.id, number), title,
            body: typeof b.body === 'string' ? b.body : '', state: 'open',
            labels: labelNames, author: VIEWER.login, createdSeq: nextSeq(),
            createdAt: nowIso(), updatedAt: nowIso(), comments: [],
          };
          repo.issues.push(issue);
          touch();
          sendJson(res, 201, issueShape(repo, issue));
          return true;
        }
        sendError(res, 405, 'Method Not Allowed');
        return true;
      }
      const num = parseInt(rest[1], 10);
      const issue = repo.issues.find((i) => i.number === num);
      if (rest.length === 2) {
        if (!issue) { sendError(res, 404, 'Not Found'); return true; }
        if (method === 'GET') { sendJson(res, 200, issueShape(repo, issue)); return true; }
        if (method === 'PATCH') {
          const b = obj(body);
          if (typeof b.title === 'string') issue.title = b.title;
          if (typeof b.body === 'string') issue.body = b.body;
          if (b.state === 'open' || b.state === 'closed') issue.state = b.state;
          if (Array.isArray(b.labels)) {
            const names: string[] = [];
            for (const l of b.labels) {
              const n = typeof l === 'string' ? l : obj(l).name;
              if (typeof n !== 'string') continue;
              if (!repo.labels.has(n)) { sendError(res, 422, `Label '${n}' does not exist`); return true; }
              names.push(n);
            }
            issue.labels = names;
          }
          issue.updatedAt = nowIso();
          touch();
          sendJson(res, 200, issueShape(repo, issue));
          return true;
        }
        sendError(res, 405, 'Method Not Allowed');
        return true;
      }
      if (rest[2] === 'comments') {
        if (!issue) { sendError(res, 404, 'Not Found'); return true; }
        if (method === 'GET') {
          sendPage(res, issue.comments.map((c) => commentShape(repo, issue, c)), url, origin);
          return true;
        }
        if (method === 'POST') {
          const b = obj(body);
          const text = typeof b.body === 'string' ? b.body : '';
          if (!text) { sendError(res, 422, 'body is required'); return true; }
          const id = nextCommentId; nextCommentId += 1;
          const comment: Comment = { id, globalId: globalId('comment', repo.id, issue.number, id), body: text, author: VIEWER.login, createdSeq: nextSeq(), createdAt: nowIso(), updatedAt: nowIso() };
          issue.comments.push(comment);
          issue.updatedAt = nowIso();
          touch();
          sendJson(res, 201, commentShape(repo, issue, comment));
          return true;
        }
        sendError(res, 405, 'Method Not Allowed');
        return true;
      }
      sendError(res, 404, 'Not Found');
      return true;
    }
    // pulls
    if (rest[0] === 'pulls') {
      if (rest.length === 1) {
        if (method === 'GET') {
          const state = url.searchParams.get('state') ?? 'open';
          let list = repo.pulls.filter((p) => state === 'all' || p.state === state);
          list = [...list].sort((a, b) => b.createdSeq - a.createdSeq);
          sendPage(res, list.map((p) => pullShape(repo, p)), url, origin);
          return true;
        }
        if (method === 'POST') {
          const b = obj(body);
          const title = typeof b.title === 'string' ? b.title : '';
          const head = typeof b.head === 'string' ? b.head : '';
          const base = typeof b.base === 'string' ? b.base : repo.defaultBranch;
          if (!title || !head) { sendError(res, 422, 'title and head are required'); return true; }
          const headRef = `refs/heads/${head}`;
          const baseRef = `refs/heads/${base}`;
          const headSha = repo.refs.get(headRef);
          const baseSha = repo.refs.get(baseRef);
          if (!headSha || !baseSha) { sendError(res, 422, 'head or base branch does not exist'); return true; }
          const number = repo.nextNumber; repo.nextNumber += 1;
          const pull: Pull = {
            number, globalId: globalId('pr', repo.id, number), title,
            body: typeof b.body === 'string' ? b.body : '',
            headRef: head, headSha, baseRef: base, baseSha,
            state: 'open', merged: false, mergedAt: null, mergeCommitSha: null,
            createdSeq: nextSeq(), createdAt: nowIso(), updatedAt: nowIso(),
          };
          repo.pulls.push(pull);
          touch();
          sendJson(res, 201, pullShape(repo, pull));
          return true;
        }
        sendError(res, 405, 'Method Not Allowed');
        return true;
      }
      const num = parseInt(rest[1], 10);
      const pull = repo.pulls.find((p) => p.number === num);
      if (rest.length === 2) {
        if (!pull) { sendError(res, 404, 'Not Found'); return true; }
        if (method === 'GET') { sendJson(res, 200, pullShape(repo, pull)); return true; }
        if (method === 'PATCH') {
          const b = obj(body);
          if (typeof b.title === 'string') pull.title = b.title;
          if (typeof b.body === 'string') pull.body = b.body;
          if (b.state === 'open' || b.state === 'closed') pull.state = b.state;
          pull.updatedAt = nowIso();
          touch();
          sendJson(res, 200, pullShape(repo, pull));
          return true;
        }
        sendError(res, 405, 'Method Not Allowed');
        return true;
      }
      if (rest[2] === 'files' && method === 'GET') {
        if (!pull) { sendError(res, 404, 'Not Found'); return true; }
        const headInfo = commitOf(repo, pull.headSha);
        const baseInfo = commitOf(repo, baseTipSha(repo, pull));
        if (!headInfo || !baseInfo) { sendJson(res, 200, []); return true; }
        const headFlat = flattenTree(repo, headInfo.tree);
        const baseFlat = flattenTree(repo, baseInfo.tree);
        const files: Array<Record<string, unknown>> = [];
        const paths = new Set([...headFlat.keys(), ...baseFlat.keys()]);
        for (const path of [...paths].sort()) {
          const h = headFlat.get(path);
          const bse = baseFlat.get(path);
          if (h && !bse) {
            const blob = repo.objects.get(h.sha);
            const lines = blob ? blob.data.toString('utf8').split('\n').length : 0;
            files.push({ sha: h.sha, filename: path, status: 'added', additions: lines, deletions: 0, changes: lines, blob_url: '', raw_url: '', contents_url: '' });
          } else if (!h && bse) {
            const blob = repo.objects.get(bse.sha);
            const lines = blob ? blob.data.toString('utf8').split('\n').length : 0;
            files.push({ sha: bse.sha, filename: path, status: 'removed', additions: 0, deletions: lines, changes: lines, blob_url: '', raw_url: '', contents_url: '' });
          } else if (h && bse && h.sha !== bse.sha) {
            const oldBlob = repo.objects.get(bse.sha);
            const newBlob = repo.objects.get(h.sha);
            const d = lineDiff(oldBlob ? oldBlob.data.toString('utf8') : '', newBlob ? newBlob.data.toString('utf8') : '');
            files.push({ sha: h.sha, filename: path, status: 'modified', additions: d.additions, deletions: d.deletions, changes: d.additions + d.deletions, blob_url: '', raw_url: '', contents_url: '' });
          }
        }
        sendPage(res, files, url, origin);
        return true;
      }
      if (rest[2] === 'merge' && method === 'PUT') {
        if (!pull) { sendError(res, 404, 'Not Found'); return true; }
        if (pull.merged) { sendError(res, 405, 'Pull request is already merged'); return true; }
        if (pull.state !== 'open') { sendError(res, 405, 'Pull request is not open'); return true; }
        const b = obj(body);
        const mergeMethod = typeof b.merge_method === 'string' ? b.merge_method : 'merge';
        if (mergeableOf(repo, pull) === 'CONFLICTING') { sendError(res, 405, 'Merge conflict'); return true; }
        const headInfo = commitOf(repo, pull.headSha);
        const baseTip = baseTipSha(repo, pull);
        const baseInfo = commitOf(repo, baseTip);
        if (!headInfo || !baseInfo) { sendError(res, 422, 'Cannot merge: missing commits'); return true; }
        // Squash: one new commit on the base branch carrying the head tree.
        const message = typeof b.commit_message === 'string' ? b.commit_message : `${pull.title} (#${pull.number})`;
        const mergeCommit = buildCommit(headInfo.tree, [baseTip], mergeMethod === 'squash' ? message : `Merge pull request #${pull.number} from ${pull.headRef}`);
        repo.objects.set(mergeCommit.sha, { type: 'commit', data: mergeCommit.data });
        repo.refs.set(`refs/heads/${pull.baseRef}`, mergeCommit.sha);
        pull.merged = true;
        pull.state = 'closed';
        pull.mergedAt = nowIso();
        pull.mergeCommitSha = mergeCommit.sha;
        pull.updatedAt = nowIso();
        touch();
        sendJson(res, 200, { sha: mergeCommit.sha, merged: true, message: 'Pull Request successfully merged' });
        return true;
      }
      sendError(res, 404, 'Not Found');
      return true;
    }
    sendError(res, 404, 'Not Found');
    return true;
  }
  return false;
}
function commitShape(r: Repo, sha: string, info: CommitInfo): Record<string, unknown> {
  const parseIdent = (s: string): { name: string; email: string; date: string } => {
    const m = /^(.*?) <(.*?)> (\d+) ([+-]\d{4})$/.exec(s);
    if (!m) return { name: s, email: '', date: nowIso() };
    return { name: m[1], email: m[2], date: new Date(parseInt(m[3], 10) * 1000).toISOString() };
  };
  const author = parseIdent(info.author);
  const committer = parseIdent(info.committer);
  return {
    sha, node_id: globalId('commit', sha),
    commit: { author, committer, message: info.message.replace(/\n+$/, ''), tree: { sha: info.tree, url: '' }, comment_count: 0, verification: { verified: false, reason: 'unsigned', signature: null, payload: null } },
    url: `/repos/${r.owner}/${r.name}/commits/${sha}`, html_url: `https://example.invalid/${r.owner}/${r.name}/commit/${sha}`,
    author: userShape(author.name === VIEWER.name ? VIEWER.login : VIEWER.login),
    committer: userShape(committer.name === VIEWER.name ? VIEWER.login : VIEWER.login),
    parents: info.parents.map((p) => ({ sha: p, url: '', html_url: '' })),
  };
}
function commentShape(r: Repo, i: Issue, c: Comment): Record<string, unknown> {
  return {
    id: c.id, node_id: c.globalId, body: c.body, user: userShape(c.author),
    created_at: c.createdAt, updated_at: c.updatedAt,
    html_url: `https://example.invalid/${r.owner}/${r.name}/issues/${i.number}#issuecomment-${c.id}`,
    url: `/repos/${r.owner}/${r.name}/issues/comments/${c.id}`,
    issue_url: `/repos/${r.owner}/${r.name}/issues/${i.number}`,
  };
}

// ---------------------------------------------------------------- GraphQL v4

type GqlValue = string | number | boolean | null | GqlValue[] | { [k: string]: GqlValue } | { __var: string } | { __enum: string };
interface GqlField { name: string; alias: string | null; args: Record<string, GqlValue>; selections: GqlField[] | null; inlineType: string | null; fragment: string | null }
interface GqlOp { kind: 'query' | 'mutation'; name: string | null; varDefs: Record<string, GqlValue>; selections: GqlField[] }
interface GqlDoc { ops: GqlOp[]; fragments: Record<string, GqlField[]> }

function gqlTokenize(src: string): Array<{ t: string; v: string }> {
  const toks: Array<{ t: string; v: string }> = [];
  let i = 0;
  while (i < src.length) {
    const c = src[i];
    if (c === ' ' || c === '\t' || c === '\n' || c === '\r' || c === ',' || c === '\uFEFF') { i += 1; continue; }
    if (c === '#') { while (i < src.length && src[i] !== '\n') i += 1; continue; }
    if (c === '.' && src.slice(i, i + 3) === '...') { toks.push({ t: '...', v: '...' }); i += 3; continue; }
    if ('{}()[]:!=$@&|'.includes(c)) { toks.push({ t: c, v: c }); i += 1; continue; }
    if (c === '"') {
      if (src.slice(i, i + 3) === '"""') {
        const end = src.indexOf('"""', i + 3);
        toks.push({ t: 'string', v: end < 0 ? src.slice(i + 3) : src.slice(i + 3, end) });
        i = end < 0 ? src.length : end + 3;
        continue;
      }
      let j = i + 1;
      let out = '';
      while (j < src.length && src[j] !== '"') {
        if (src[j] === '\\' && j + 1 < src.length) { const e = src[j + 1]; out += e === 'n' ? '\n' : e === 't' ? '\t' : e === 'r' ? '\r' : e; j += 2; }
        else { out += src[j]; j += 1; }
      }
      toks.push({ t: 'string', v: out });
      i = j + 1;
      continue;
    }
    if (/[0-9-]/.test(c)) {
      let j = i;
      while (j < src.length && /[0-9.eE+-]/.test(src[j])) j += 1;
      toks.push({ t: 'number', v: src.slice(i, j) });
      i = j;
      continue;
    }
    if (/[A-Za-z_]/.test(c)) {
      let j = i;
      while (j < src.length && /[A-Za-z0-9_]/.test(src[j])) j += 1;
      toks.push({ t: 'name', v: src.slice(i, j) });
      i = j;
      continue;
    }
    i += 1;
  }
  return toks;
}
function gqlParse(src: string): GqlDoc {
  const toks = gqlTokenize(src);
  let pos = 0;
  const peek = (): { t: string; v: string } | null => toks[pos] ?? null;
  const next = (): { t: string; v: string } => toks[pos++] as { t: string; v: string };
  const expect = (t: string): { t: string; v: string } => { const tok = next(); if (!tok || tok.t !== t) throw new Error(`expected ${t}, got ${tok?.t ?? 'eof'}`); return tok; };
  const parseValue = (): GqlValue => {
    const tok = next();
    if (!tok) throw new Error('unexpected eof in value');
    if (tok.t === '$') { const n = next(); return { __var: n.v }; }
    if (tok.t === 'string') return tok.v;
    if (tok.t === 'number') return tok.v.includes('.') || tok.v.includes('e') || tok.v.includes('E') ? parseFloat(tok.v) : parseInt(tok.v, 10);
    if (tok.t === '[') {
      const arr: GqlValue[] = [];
      while (peek() && peek()!.t !== ']') arr.push(parseValue());
      expect(']');
      return arr;
    }
    if (tok.t === '{') {
      const o: Record<string, GqlValue> = {};
      while (peek() && peek()!.t !== '}') { const k = next(); expect(':'); o[k.v] = parseValue(); }
      expect('}');
      return o;
    }
    if (tok.t === 'name') {
      if (tok.v === 'true') return true;
      if (tok.v === 'false') return false;
      if (tok.v === 'null') return null;
      return { __enum: tok.v };
    }
    throw new Error(`unexpected token ${tok.t} in value`);
  };
  const parseArgs = (): Record<string, GqlValue> => {
    const args: Record<string, GqlValue> = {};
    expect('(');
    while (peek() && peek()!.t !== ')') { const k = next(); expect(':'); args[k.v] = parseValue(); }
    expect(')');
    return args;
  };
  const parseSelectionSet = (): GqlField[] => {
    expect('{');
    const fields: GqlField[] = [];
    while (peek() && peek()!.t !== '}') {
      if (peek()!.t === '...') {
        next();
        if (peek() && peek()!.t === 'name' && peek()!.v === 'on') {
          next();
          const typeName = next().v;
          const sels = parseSelectionSet();
          fields.push({ name: '', alias: null, args: {}, selections: sels, inlineType: typeName, fragment: null });
        } else {
          const fragName = next().v;
          fields.push({ name: '', alias: null, args: {}, selections: null, inlineType: null, fragment: fragName });
        }
        continue;
      }
      const first = next();
      let alias: string | null = null;
      let name = first.v;
      if (peek() && peek()!.t === ':') { next(); alias = name; name = next().v; }
      let args: Record<string, GqlValue> = {};
      if (peek() && peek()!.t === '(') args = parseArgs();
      while (peek() && peek()!.t === '@') { next(); next(); if (peek() && peek()!.t === '(') parseArgs(); }
      let sels: GqlField[] | null = null;
      if (peek() && peek()!.t === '{') sels = parseSelectionSet();
      fields.push({ name, alias, args, selections: sels, inlineType: null, fragment: null });
    }
    expect('}');
    return fields;
  };
  const doc: GqlDoc = { ops: [], fragments: {} };
  while (peek()) {
    const tok = peek()!;
    if (tok.t === '{') {
      doc.ops.push({ kind: 'query', name: null, varDefs: {}, selections: parseSelectionSet() });
    } else if (tok.t === 'name' && (tok.v === 'query' || tok.v === 'mutation')) {
      next();
      let name: string | null = null;
      if (peek() && peek()!.t === 'name') name = next().v;
      const varDefs: Record<string, GqlValue> = {};
      if (peek() && peek()!.t === '(') {
        expect('(');
        while (peek() && peek()!.t !== ')') {
          expect('$');
          const vn = next().v;
          expect(':');
          // skip the type (name, possibly [..] and !)
          let depth = 0;
          while (peek()) {
            const tt = peek()!;
            if (tt.t === '[') { depth += 1; next(); continue; }
            if (tt.t === ']') { depth -= 1; next(); continue; }
            if (tt.t === '!' || tt.t === 'name') { next(); continue; }
            break;
          }
          if (peek() && peek()!.t === '=') { next(); varDefs[vn] = parseValue(); }
        }
        expect(')');
      }
      while (peek() && peek()!.t === '@') { next(); next(); if (peek() && peek()!.t === '(') parseArgs(); }
      doc.ops.push({ kind: tok.v as 'query' | 'mutation', name, varDefs, selections: parseSelectionSet() });
    } else if (tok.t === 'name' && tok.v === 'fragment') {
      next();
      const fragName = next().v;
      expect('name'); // 'on'
      next(); // type name
      doc.fragments[fragName] = parseSelectionSet();
    } else {
      next();
    }
  }
  return doc;
}
function resolveValue(v: GqlValue, vars: Record<string, unknown>): unknown {
  if (v !== null && typeof v === 'object' && !Array.isArray(v)) {
    if ('__var' in v) return vars[(v as { __var: string }).__var];
    if ('__enum' in v) return (v as { __enum: string }).__enum;
    const o: Record<string, unknown> = {};
    for (const [k, val] of Object.entries(v)) o[k] = resolveValue(val as GqlValue, vars);
    return o;
  }
  if (Array.isArray(v)) return v.map((x) => resolveValue(x, vars));
  return v;
}
function argVal(args: Record<string, GqlValue>, name: string, vars: Record<string, unknown>): unknown {
  if (!(name in args)) return undefined;
  return resolveValue(args[name], vars);
}
const TYPE_FIELDS: Record<string, string[]> = {
  Issue: ['id', 'number', 'title', 'state', 'body', 'author', 'createdAt', 'updatedAt', 'closedAt', 'labels', 'comments', 'url'],
  PullRequest: ['id', 'number', 'headRefName', 'baseRefName', 'mergeable', 'state', 'merged', 'files', 'title', 'body', 'author', 'createdAt', 'updatedAt', 'headRef', 'baseRef', 'url'],
  Repository: ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequests', 'pullRequest', 'description', 'isPrivate', 'url', 'createdAt', 'updatedAt'],
  User: ['id', 'login', 'name', 'email', 'avatarUrl'],
  Ref: ['name', 'target'],
  IssueConnection: ['nodes', 'edges', 'pageInfo', 'totalCount'],
  PullRequestConnection: ['nodes', 'edges', 'pageInfo', 'totalCount'],
  PageInfo: ['hasNextPage', 'hasPreviousPage', 'startCursor', 'endCursor'],
  Comment: ['id', 'body', 'author', 'createdAt'],
  CommentEdge: ['node', 'cursor'],
  Label: ['name', 'color', 'description'],
  LabelConnection: ['nodes', 'totalCount'],
  IssueCommentConnection: ['nodes', 'totalCount'],
  PullRequestFileConnection: ['nodes', 'totalCount'],
  PullRequestFile: ['path', 'additions', 'deletions', 'changeType'],
  SearchType: [],
  Commit: ['oid', 'message', 'author'],
};
function issueCursor(repoId: number, number: number): string { return b64url(`cursor:${repoId}:${number}`); }
function decodeCursor(c: string): { repoId: number; number: number } | null {
  const parts = b64decode(c).split(':');
  if (parts.length !== 3 || parts[0] !== 'cursor') return null;
  return { repoId: parseInt(parts[1], 10), number: parseInt(parts[2], 10) };
}
interface GqlCtx { errors: Array<{ message: string }>; doc: GqlDoc }
function resolveSelections(ctx: GqlCtx, typeName: string, value: Record<string, unknown>, fields: GqlField[], vars: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const f of fields) {
    if (f.fragment) {
      const frag = ctx.doc.fragments[f.fragment];
      if (frag) Object.assign(out, resolveSelections(ctx, typeName, value, frag, vars));
      continue;
    }
    if (f.inlineType) {
      if (f.inlineType === typeName || (value as Record<string, unknown>).__typename === f.inlineType) {
        Object.assign(out, resolveSelections(ctx, typeName, value, f.selections ?? [], vars));
      }
      continue;
    }
    const key = f.alias ?? f.name;
    if (f.name === '__typename') { out[key] = typeName; continue; }
    const allowed = TYPE_FIELDS[typeName];
    if (allowed && !allowed.includes(f.name)) {
      ctx.errors.push({ message: `Field '${f.name}' doesn't exist on type '${typeName}'` });
      out[key] = null;
      continue;
    }
    out[key] = resolveField(ctx, typeName, value, f, vars);
  }
  return out;
}
function resolveField(ctx: GqlCtx, typeName: string, value: Record<string, unknown>, f: GqlField, vars: Record<string, unknown>): unknown {
  const v = value as Record<string, unknown>;
  const sub = (val: unknown, subType: string): unknown => {
    if (val === null || val === undefined) return null;
    if (f.selections === null) return val;
    if (Array.isArray(val)) return val.map((x) => resolveSelections(ctx, subType, x as Record<string, unknown>, f.selections!, vars));
    return resolveSelections(ctx, subType, val as Record<string, unknown>, f.selections, vars);
  };
  switch (typeName) {
    case 'Query': return resolveQueryField(ctx, v, f, vars);
    case 'Mutation': return resolveMutationField(ctx, v, f, vars);
    case 'Repository': return resolveRepoField(ctx, v, f, vars, sub);
    case 'Issue': return resolveIssueField(ctx, v, f, vars, sub);
    case 'PullRequest': return resolvePullField(ctx, v, f, vars, sub);
    case 'IssueConnection':
    case 'PullRequestConnection': {
      if (f.name === 'nodes') return sub(v.nodes, typeName === 'IssueConnection' ? 'Issue' : 'PullRequest');
      if (f.name === 'edges') return sub(v.edges, 'IssueEdge');
      if (f.name === 'pageInfo') return sub(v.pageInfo, 'PageInfo');
      return v[f.name] ?? null;
    }
    case 'PageInfo': case 'User': case 'Ref': case 'Comment': case 'Label': case 'Commit':
      return v[f.name] ?? null;
    case 'CommentEdge': {
      if (f.name === 'node') return sub(v.node, 'Comment');
      return v[f.name] ?? null;
    }
    case 'LabelConnection':
    case 'IssueCommentConnection':
    case 'PullRequestFileConnection': {
      if (f.name === 'nodes') return sub(v.nodes, typeName === 'LabelConnection' ? 'Label' : typeName === 'IssueCommentConnection' ? 'Comment' : 'PullRequestFile');
      return v[f.name] ?? null;
    }
    case '__Type': {
      if (f.name === 'fields') return sub(v.fields, '__Field');
      if (f.name === 'enumValues') return sub(v.enumValues, '__EnumValue');
      return v[f.name] ?? null;
    }
    case '__Field': case '__EnumValue': return v[f.name] ?? null;
    default: return v[f.name] ?? null;
  }
}
function resolveQueryField(ctx: GqlCtx, _v: Record<string, unknown>, f: GqlField, vars: Record<string, unknown>): unknown {
  if (f.name === 'viewer') {
    const user = { __typename: 'User', id: VIEWER.id, login: VIEWER.login, name: VIEWER.name, email: VIEWER.email, avatarUrl: `https://example.invalid/avatar/${VIEWER.login}` };
    return f.selections ? resolveSelections(ctx, 'User', user, f.selections, vars) : user;
  }
  if (f.name === 'repository') {
    const owner = String(argVal(f.args, 'owner', vars) ?? '');
    const name = String(argVal(f.args, 'name', vars) ?? '');
    const repo = getRepo(owner, name);
    if (!repo || owner !== VIEWER.login) return null;
    const val = repoValue(repo);
    return f.selections ? resolveSelections(ctx, 'Repository', val, f.selections, vars) : val;
  }
  if (f.name === 'node') {
    const id = String(argVal(f.args, 'id', vars) ?? '');
    const decoded = b64decode(id);
    const parts = decoded.split(':');
    if (parts[0] !== 'forge') return null;
    if (parts[1] === 'repo') {
      const repo = [...repos.values()].find((r) => r.id === parseInt(parts[2], 10));
      if (!repo) return null;
      const val = repoValue(repo);
      return f.selections ? resolveSelections(ctx, 'Repository', val, f.selections, vars) : val;
    }
    if (parts[1] === 'issue') {
      const repo = [...repos.values()].find((r) => r.id === parseInt(parts[2], 10));
      const issue = repo?.issues.find((i) => i.number === parseInt(parts[3], 10));
      if (!repo || !issue) return null;
      const val = issueValue(repo, issue);
      return f.selections ? resolveSelections(ctx, 'Issue', val, f.selections, vars) : val;
    }
    if (parts[1] === 'pr') {
      const repo = [...repos.values()].find((r) => r.id === parseInt(parts[2], 10));
      const pull = repo?.pulls.find((p) => p.number === parseInt(parts[3], 10));
      if (!repo || !pull) return null;
      const val = pullValue(repo, pull);
      return f.selections ? resolveSelections(ctx, 'PullRequest', val, f.selections, vars) : val;
    }
    return null;
  }
  if (f.name === '__type') {
    const name = String(argVal(f.args, 'name', vars) ?? '');
    let val: Record<string, unknown> | null = null;
    if (name === 'SearchType') {
      val = { __typename: '__Type', name, kind: 'ENUM', fields: null, enumValues: [{ name: 'ISSUE' }, { name: 'REPOSITORY' }, { name: 'USER' }] };
    } else if (TYPE_FIELDS[name]) {
      val = { __typename: '__Type', name, kind: 'OBJECT', fields: TYPE_FIELDS[name].map((n) => ({ name: n })), enumValues: null };
    } else return null;
    return f.selections ? resolveSelections(ctx, '__Type', val, f.selections, vars) : val;
  }
  if (f.name === '__schema') {
    const val = { __typename: '__Schema', queryType: { name: 'Query' }, mutationType: { name: 'Mutation' }, types: [] };
    return f.selections ? { queryType: { name: 'Query' }, mutationType: { name: 'Mutation' } } : val;
  }
  ctx.errors.push({ message: `Field '${f.name}' doesn't exist on type 'Query'` });
  return null;
}
function repoValue(r: Repo): Record<string, unknown> {
  return {
    __typename: 'Repository', __repo: r, id: globalId('repo', r.id), databaseId: r.id, name: r.name,
    nameWithOwner: `${r.owner}/${r.name}`, owner: { __typename: 'User', id: VIEWER.id, login: r.owner, name: VIEWER.name, email: VIEWER.email },
    defaultBranchRef: { __typename: 'Ref', name: r.defaultBranch, target: null },
    viewerPermission: 'ADMIN', hasIssuesEnabled: true, description: r.description, isPrivate: r.private,
    url: `https://example.invalid/${r.owner}/${r.name}`, createdAt: r.createdAt, updatedAt: r.updatedAt,
  };
}
function issueValue(r: Repo, i: Issue): Record<string, unknown> {
  return {
    __typename: 'Issue', __repo: r, __issue: i, id: i.globalId, number: i.number, title: i.title,
    body: i.body, state: i.state === 'open' ? 'OPEN' : 'CLOSED', author: { __typename: 'User', id: VIEWER.id, login: i.author, name: VIEWER.name, email: VIEWER.email },
    createdAt: i.createdAt, updatedAt: i.updatedAt, closedAt: i.state === 'closed' ? i.updatedAt : null,
    labels: { __typename: 'LabelConnection', nodes: i.labels.map((n) => ({ __typename: 'Label', name: n, color: r.labels.get(n)?.color ?? '000000', description: r.labels.get(n)?.description ?? '' })), totalCount: i.labels.length },
    comments: { __typename: 'IssueCommentConnection', nodes: i.comments.map((c) => ({ __typename: 'Comment', id: c.globalId, body: c.body, author: { __typename: 'User', id: VIEWER.id, login: c.author }, createdAt: c.createdAt })) },
    url: `https://example.invalid/${r.owner}/${r.name}/issues/${i.number}`,
  };
}
function pullValue(r: Repo, p: Pull): Record<string, unknown> {
  return {
    __typename: 'PullRequest', __repo: r, __pull: p, id: p.globalId, number: p.number, title: p.title,
    body: p.body, state: p.state === 'open' ? 'OPEN' : 'CLOSED', merged: p.merged, mergeable: mergeableOf(r, p),
    headRefName: p.headRef, baseRefName: p.baseRef,
    headRef: { __typename: 'Ref', name: p.headRef, target: null },
    baseRef: { __typename: 'Ref', name: p.baseRef, target: null },
    author: { __typename: 'User', id: VIEWER.id, login: VIEWER.login, name: VIEWER.name, email: VIEWER.email },
    createdAt: p.createdAt, updatedAt: p.updatedAt,
    url: `https://example.invalid/${r.owner}/${r.name}/pull/${p.number}`,
  };
}
function resolveRepoField(ctx: GqlCtx, v: Record<string, unknown>, f: GqlField, vars: Record<string, unknown>, sub: (val: unknown, subType: string) => unknown): unknown {
  const r = v.__repo as Repo;
  if (f.name === 'owner') return sub(v.owner, 'User');
  if (f.name === 'defaultBranchRef') return sub(v.defaultBranchRef, 'Ref');
  if (f.name === 'issue') {
    const num = Number(argVal(f.args, 'number', vars));
    const issue = r.issues.find((i) => i.number === num);
    if (!issue) return null;
    return sub(issueValue(r, issue), 'Issue');
  }
  if (f.name === 'issues') {
    const first = Number(argVal(f.args, 'first', vars) ?? 100);
    const after = argVal(f.args, 'after', vars);
    const states = argVal(f.args, 'states', vars) as string[] | undefined;
    const orderBy = argVal(f.args, 'orderBy', vars) as Record<string, unknown> | undefined;
    let list = [...r.issues];
    const wanted = states && states.length > 0 ? states.map((s) => String(s).toLowerCase()) : ['open'];
    list = list.filter((i) => wanted.includes(i.state));
    const dir = String(orderBy?.direction ?? 'DESC');
    list.sort((a, b) => {
      const cmp = a.createdSeq - b.createdSeq || a.number - b.number;
      return dir === 'ASC' ? cmp : -cmp;
    });
    if (typeof after === 'string') {
      const cur = decodeCursor(after);
      if (cur) {
        const idx = list.findIndex((i) => i.number === cur.number);
        if (idx >= 0) list = list.slice(idx + 1);
      }
    }
    const page = list.slice(0, first);
    const hasNext = list.length > first;
    const endCursor = page.length ? issueCursor(r.id, page[page.length - 1].number) : null;
    const conn = { __typename: 'IssueConnection', nodes: page.map((i) => issueValue(r, i)), pageInfo: { __typename: 'PageInfo', hasNextPage: hasNext, hasPreviousPage: false, startCursor: page.length ? issueCursor(r.id, page[0].number) : null, endCursor }, totalCount: list.length };
    return sub(conn, 'IssueConnection');
  }
  if (f.name === 'pullRequest') {
    const num = Number(argVal(f.args, 'number', vars));
    const pull = r.pulls.find((p) => p.number === num);
    if (!pull) return null;
    return sub(pullValue(r, pull), 'PullRequest');
  }
  if (f.name === 'pullRequests') {
    const first = Number(argVal(f.args, 'first', vars) ?? 100);
    const states = argVal(f.args, 'states', vars) as string[] | undefined;
    let list = [...r.pulls];
    const wanted = states && states.length > 0 ? states.map((s) => String(s).toLowerCase()) : ['open'];
    list = list.filter((p) => wanted.includes(p.state));
    list.sort((a, b) => b.createdSeq - a.createdSeq);
    const page = list.slice(0, first);
    const conn = { __typename: 'PullRequestConnection', nodes: page.map((p) => pullValue(r, p)), pageInfo: { __typename: 'PageInfo', hasNextPage: list.length > first, hasPreviousPage: false, startCursor: null, endCursor: null }, totalCount: list.length };
    return sub(conn, 'PullRequestConnection');
  }
  return v[f.name] ?? null;
}
function resolveIssueField(ctx: GqlCtx, v: Record<string, unknown>, f: GqlField, vars: Record<string, unknown>, sub: (val: unknown, subType: string) => unknown): unknown {
  if (f.name === 'author') return sub(v.author, 'User');
  if (f.name === 'labels') return sub(v.labels, 'LabelConnection');
  if (f.name === 'comments') {
    const nodes = (v.comments as Record<string, unknown>).nodes as unknown[];
    return sub({ __typename: 'IssueCommentConnection', nodes, totalCount: nodes.length }, 'IssueCommentConnection');
  }
  return v[f.name] ?? null;
}
function prFiles(r: Repo, p: Pull): Array<Record<string, unknown>> {
  const headInfo = commitOf(r, p.headSha);
  const baseInfo = commitOf(r, baseTipSha(r, p));
  if (!headInfo || !baseInfo) return [];
  const headFlat = flattenTree(r, headInfo.tree);
  const baseFlat = flattenTree(r, baseInfo.tree);
  const out: Array<Record<string, unknown>> = [];
  const paths = new Set([...headFlat.keys(), ...baseFlat.keys()]);
  for (const path of [...paths].sort()) {
    const h = headFlat.get(path);
    const b = baseFlat.get(path);
    if (h && !b) {
      const blob = r.objects.get(h.sha);
      const lines = blob ? blob.data.toString('utf8').split('\n').length : 0;
      out.push({ __typename: 'PullRequestFile', path, additions: lines, deletions: 0, changeType: 'ADDED' });
    } else if (!h && b) {
      const blob = r.objects.get(b.sha);
      const lines = blob ? blob.data.toString('utf8').split('\n').length : 0;
      out.push({ __typename: 'PullRequestFile', path, additions: 0, deletions: lines, changeType: 'DELETED' });
    } else if (h && b && h.sha !== b.sha) {
      const d = lineDiff(r.objects.get(b.sha)?.data.toString('utf8') ?? '', r.objects.get(h.sha)?.data.toString('utf8') ?? '');
      out.push({ __typename: 'PullRequestFile', path, additions: d.additions, deletions: d.deletions, changeType: 'MODIFIED' });
    }
  }
  return out;
}
function resolvePullField(ctx: GqlCtx, v: Record<string, unknown>, f: GqlField, vars: Record<string, unknown>, sub: (val: unknown, subType: string) => unknown): unknown {
  const r = v.__repo as Repo;
  const p = v.__pull as Pull;
  if (f.name === 'files') {
    const first = Number(argVal(f.args, 'first', vars) ?? 100);
    const files = prFiles(r, p).slice(0, first);
    return sub({ __typename: 'PullRequestFileConnection', nodes: files, totalCount: files.length }, 'PullRequestFileConnection');
  }
  if (f.name === 'author') return sub(v.author, 'User');
  if (f.name === 'headRef' || f.name === 'baseRef') return sub(v[f.name], 'Ref');
  return v[f.name] ?? null;
}
function resolveMutationField(ctx: GqlCtx, _v: Record<string, unknown>, f: GqlField, vars: Record<string, unknown>): unknown {
  const input = (argVal(f.args, 'input', vars) ?? {}) as Record<string, unknown>;
  const subSel = (val: unknown, subType: string, field: GqlField): unknown => {
    if (val === null || val === undefined) return null;
    if (field.selections === null) return val;
    if (Array.isArray(val)) return val.map((x) => resolveSelections(ctx, subType, x as Record<string, unknown>, field.selections!, vars));
    return resolveSelections(ctx, subType, val as Record<string, unknown>, field.selections, vars);
  };
  const wrap = (payload: Record<string, { value: unknown; type: string }>): unknown => {
    if (!f.selections) {
      const raw: Record<string, unknown> = {};
      for (const [k, e] of Object.entries(payload)) raw[k] = e.value;
      return raw;
    }
    const out: Record<string, unknown> = {};
    for (const pf of f.selections) {
      const entry = payload[pf.name];
      if (!entry) { ctx.errors.push({ message: `Field '${pf.name}' doesn't exist on mutation payload` }); out[pf.alias ?? pf.name] = null; continue; }
      out[pf.alias ?? pf.name] = subSel(entry.value, entry.type, pf);
    }
    return out;
  };
  if (f.name === 'createIssue') {
    const repoId = String(input.repositoryId ?? '');
    const repo = [...repos.values()].find((r) => globalId('repo', r.id) === repoId);
    if (!repo) { ctx.errors.push({ message: 'Could not resolve to a Repository with the provided id' }); return wrap({ issue: { value: null, type: 'Issue' } }); }
    const number = repo.nextNumber; repo.nextNumber += 1;
    const issue: Issue = { number, globalId: globalId('issue', repo.id, number), title: String(input.title ?? ''), body: typeof input.body === 'string' ? input.body : '', state: 'open', labels: [], author: VIEWER.login, createdSeq: nextSeq(), createdAt: nowIso(), updatedAt: nowIso(), comments: [] };
    repo.issues.push(issue);
    repo.updatedAt = nowIso(); repo.version += 1;
    return wrap({ issue: { value: issueValue(repo, issue), type: 'Issue' } });
  }
  if (f.name === 'closeIssue') {
    const issueId = String(input.issueId ?? '');
    const decoded = b64decode(issueId).split(':');
    const repo = [...repos.values()].find((r) => r.id === parseInt(decoded[2] ?? '', 10));
    const issue = repo?.issues.find((i) => i.number === parseInt(decoded[3] ?? '', 10));
    if (!repo || !issue) { ctx.errors.push({ message: 'Could not resolve to an Issue with the provided id' }); return wrap({ issue: { value: null, type: 'Issue' } }); }
    issue.state = 'closed';
    issue.updatedAt = nowIso();
    repo.version += 1;
    return wrap({ issue: { value: issueValue(repo, issue), type: 'Issue' } });
  }
  if (f.name === 'createPullRequest') {
    const repoId = String(input.repositoryId ?? '');
    const repo = [...repos.values()].find((r) => globalId('repo', r.id) === repoId);
    if (!repo) { ctx.errors.push({ message: 'Could not resolve to a Repository with the provided id' }); return wrap({ pullRequest: { value: null, type: 'PullRequest' } }); }
    const head = String(input.headRefName ?? '');
    const base = String(input.baseRefName ?? '');
    const headSha = repo.refs.get(`refs/heads/${head}`);
    const baseSha = repo.refs.get(`refs/heads/${base}`);
    if (!headSha || !baseSha) { ctx.errors.push({ message: 'head or base ref does not exist' }); return wrap({ pullRequest: { value: null, type: 'PullRequest' } }); }
    const number = repo.nextNumber; repo.nextNumber += 1;
    const pull: Pull = { number, globalId: globalId('pr', repo.id, number), title: String(input.title ?? ''), body: typeof input.body === 'string' ? input.body : '', headRef: head, headSha, baseRef: base, baseSha, state: 'open', merged: false, mergedAt: null, mergeCommitSha: null, createdSeq: nextSeq(), createdAt: nowIso(), updatedAt: nowIso() };
    repo.pulls.push(pull);
    repo.version += 1;
    return wrap({ pullRequest: { value: pullValue(repo, pull), type: 'PullRequest' } });
  }
  if (f.name === 'mergePullRequest') {
    const prId = String(input.pullRequestId ?? '');
    const decoded = b64decode(prId).split(':');
    const repo = [...repos.values()].find((r) => r.id === parseInt(decoded[2] ?? '', 10));
    const pull = repo?.pulls.find((p) => p.number === parseInt(decoded[3] ?? '', 10));
    if (!repo || !pull) { ctx.errors.push({ message: 'Could not resolve to a PullRequest with the provided id' }); return wrap({ pullRequest: { value: null, type: 'PullRequest' } }); }
    const method = String(input.mergeMethod ?? 'SQUASH');
    if (mergeableOf(repo, pull) === 'CONFLICTING') { ctx.errors.push({ message: 'Merge conflict' }); return wrap({ pullRequest: { value: pullValue(repo, pull), type: 'PullRequest' } }); }
    const headInfo = commitOf(repo, pull.headSha);
    if (!headInfo) { ctx.errors.push({ message: 'head commit missing' }); return wrap({ pullRequest: { value: pullValue(repo, pull), type: 'PullRequest' } }); }
    const mergeCommit = buildCommit(headInfo.tree, [baseTipSha(repo, pull)], `${pull.title} (#${pull.number})`);
    repo.objects.set(mergeCommit.sha, { type: 'commit', data: mergeCommit.data });
    repo.refs.set(`refs/heads/${pull.baseRef}`, mergeCommit.sha);
    pull.merged = true;
    pull.state = 'closed';
    pull.mergedAt = nowIso();
    pull.mergeCommitSha = mergeCommit.sha;
    pull.updatedAt = nowIso();
    repo.version += 1;
    void method;
    return wrap({ pullRequest: { value: pullValue(repo, pull), type: 'PullRequest' } });
  }
  if (f.name === 'addComment') {
    const subjectId = String(input.subjectId ?? '');
    const decoded = b64decode(subjectId).split(':');
    const repo = [...repos.values()].find((r) => r.id === parseInt(decoded[2] ?? '', 10));
    const issue = repo?.issues.find((i) => i.number === parseInt(decoded[3] ?? '', 10));
    if (!repo || !issue) { ctx.errors.push({ message: 'Could not resolve to an Issue with the provided id' }); return wrap({ commentEdge: { value: null, type: 'CommentEdge' } }); }
    const id = nextCommentId; nextCommentId += 1;
    const comment: Comment = { id, globalId: globalId('comment', repo.id, issue.number, id), body: String(input.body ?? ''), author: VIEWER.login, createdSeq: nextSeq(), createdAt: nowIso(), updatedAt: nowIso() };
    issue.comments.push(comment);
    repo.version += 1;
    const edge = { __typename: 'CommentEdge', node: { __typename: 'Comment', id: comment.globalId, body: comment.body, author: { __typename: 'User', id: VIEWER.id, login: comment.author }, createdAt: comment.createdAt }, cursor: b64url(`comment:${comment.id}`) };
    return wrap({ commentEdge: { value: edge, type: 'CommentEdge' } });
  }
  ctx.errors.push({ message: `Field '${f.name}' doesn't exist on type 'Mutation'` });
  return wrap({});
}
async function handleGraphql(req: IncomingMessage, res: ServerResponse): Promise<boolean> {
  if (!requireAuth(req, res)) return true;
  const raw = await readBody(req);
  let parsed: unknown;
  try { parsed = JSON.parse(raw.toString('utf8')); } catch { sendError(res, 400, 'Problems parsing JSON'); return true; }
  const runOne = (doc: unknown): Record<string, unknown> => {
    const body = (doc ?? {}) as Record<string, unknown>;
    const query = typeof body.query === 'string' ? body.query : '';
    const variables = (body.variables ?? {}) as Record<string, unknown>;
    const ctx: GqlCtx = { errors: [], doc: { ops: [], fragments: {} } };
    let gql: GqlDoc;
    try { gql = gqlParse(query); } catch (e) {
      return { errors: [{ message: e instanceof Error ? e.message : 'parse error' }] };
    }
    ctx.doc = gql;
    const op = gql.ops[0];
    if (!op) return { errors: [{ message: 'no operation' }] };
    const vars: Record<string, unknown> = { ...op.varDefs, ...variables };
    let data: Record<string, unknown>;
    if (op.kind === 'mutation') {
      data = {};
      for (const f of op.selections) {
        const key = f.alias ?? f.name;
        data[key] = resolveMutationField(ctx, {}, f, vars);
      }
    } else {
      data = resolveSelections(ctx, 'Query', {}, op.selections, vars);
    }
    const out: Record<string, unknown> = { data };
    if (ctx.errors.length > 0) out.errors = ctx.errors;
    return out;
  };
  if (Array.isArray(parsed)) {
    sendJson(res, 200, parsed.map(runOne));
    return true;
  }
  sendJson(res, 200, runOne(parsed));
  return true;
}

// ---------------------------------------------------------------- MCP

const MCP_TOOLS: Array<Record<string, unknown>> = [
  {
    name: 'create_repo', description: 'Create a repository for the authenticated user.',
    inputSchema: { type: 'object', properties: { name: { type: 'string', description: 'Repository name' }, description: { type: 'string', description: 'Repository description' }, private: { type: 'boolean', description: 'Whether the repository is private' } }, required: ['name'] },
  },
  {
    name: 'get_repo', description: 'Get a repository by owner and name.',
    inputSchema: { type: 'object', properties: { owner: { type: 'string', description: 'Repository owner login' }, repo: { type: 'string', description: 'Repository name' } }, required: ['owner', 'repo'] },
  },
  {
    name: 'create_issue', description: 'Create an issue in a repository.',
    inputSchema: { type: 'object', properties: { owner: { type: 'string' }, repo: { type: 'string' }, title: { type: 'string' }, body: { type: 'string' } }, required: ['owner', 'repo', 'title'] },
  },
  {
    name: 'list_issues', description: 'List issues in a repository.',
    inputSchema: { type: 'object', properties: { owner: { type: 'string' }, repo: { type: 'string' }, state: { type: 'string', description: 'open, closed or all' } }, required: ['owner', 'repo'] },
  },
  {
    name: 'create_pull_request', description: 'Open a pull request.',
    inputSchema: { type: 'object', properties: { owner: { type: 'string' }, repo: { type: 'string' }, title: { type: 'string' }, head: { type: 'string', description: 'Head branch name' }, base: { type: 'string', description: 'Base branch name' }, body: { type: 'string' } }, required: ['owner', 'repo', 'title', 'head', 'base'] },
  },
  {
    name: 'merge_pull_request', description: 'Merge a pull request.',
    inputSchema: { type: 'object', properties: { owner: { type: 'string' }, repo: { type: 'string' }, pull_number: { type: 'integer', description: 'Pull request number' } }, required: ['owner', 'repo', 'pull_number'] },
  },
  {
    name: 'close_issue', description: 'Close an issue.',
    inputSchema: { type: 'object', properties: { owner: { type: 'string' }, repo: { type: 'string' }, issue_number: { type: 'integer' } }, required: ['owner', 'repo', 'issue_number'] },
  },
  {
    name: 'list_repositories', description: 'List repositories of the authenticated user.',
    inputSchema: { type: 'object', properties: {}, required: [] },
  },
];
function mcpToolResult(obj: unknown, isError = false): Record<string, unknown> {
  const text = typeof obj === 'string' ? obj : JSON.stringify(obj);
  return { content: [{ type: 'text', text }], structuredContent: obj, isError };
}
async function handleMcp(req: IncomingMessage, res: ServerResponse): Promise<boolean> {
  const raw = await readBody(req);
  let rpc: Record<string, unknown>;
  try { rpc = JSON.parse(raw.toString('utf8')) as Record<string, unknown>; } catch {
    sendJson(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
    return true;
  }
  const id = (rpc.id ?? null) as string | number | null;
  const method = String(rpc.method ?? '');
  const params = (rpc.params ?? {}) as Record<string, unknown>;
  const ok = (result: unknown): void => sendJson(res, 200, { jsonrpc: '2.0', id, result });
  const err = (code: number, message: string, status = 200): void => sendJson(res, status, { jsonrpc: '2.0', id, error: { code, message } });
  // Notifications carry no id and get no answer.
  if (id === null && method.startsWith('notifications/')) {
    res.writeHead(202, { 'Content-Length': 0 });
    res.end();
    return true;
  }
  if (!authed(req)) {
    sendJson(res, 401, { jsonrpc: '2.0', id, error: { code: -32001, message: 'Unauthorized' } });
    return true;
  }
  if (method === 'server/discover') {
    ok({ supportedVersions: ['2026-07-28'], protocolVersion: '2026-07-28', capabilities: { tools: {} }, serverInfo: { name: 'forge', version: VERSION }, instructions: 'A GitHub-compatible git forge.' });
    return true;
  }
  if (method === 'initialize') {
    const offered = String((params as Record<string, unknown>).protocolVersion ?? '2025-11-25');
    const known = ['2026-07-28', '2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];
    const chosen = known.includes(offered) ? offered : '2025-11-25';
    ok({ protocolVersion: chosen, capabilities: { tools: {} }, serverInfo: { name: 'forge', version: VERSION } });
    return true;
  }
  if (method === 'ping') { ok({}); return true; }
  if (method === 'tools/list') {
    ok({ tools: MCP_TOOLS });
    return true;
  }
  if (method === 'tools/call') {
    const name = String(params.name ?? '');
    const args = ((params.arguments ?? {}) as Record<string, unknown>);
    const tool = MCP_TOOLS.find((t) => t.name === name);
    if (!tool) { err(-32602, `Unknown tool: ${name}`); return true; }
    const schema = tool.inputSchema as Record<string, unknown>;
    const required = (schema.required ?? []) as string[];
    const missing = required.filter((k) => args[k] === undefined || args[k] === null || args[k] === '');
    if (missing.length > 0) { ok(mcpToolResult(`Missing required argument: ${missing.join(', ')}`, true)); return true; }
    const owner = String(args.owner ?? args.owner_login ?? VIEWER.login);
    const repoName = String(args.repo ?? args.repository ?? '');
    const fullName = typeof args.full_name === 'string' ? args.full_name : '';
    const [o2, n2] = fullName.includes('/') ? fullName.split('/') : [owner, repoName];
    const getR = (): Repo | undefined => getRepo(o2, n2);
    if (name === 'create_repo') {
      const rname = String(args.name ?? '');
      if (getRepo(VIEWER.login, rname)) { ok(mcpToolResult(`Repository ${rname} already exists`, true)); return true; }
      const repo = newRepo(VIEWER.login, rname, typeof args.description === 'string' ? args.description : '', args.private === true);
      ok(mcpToolResult(repoShape(repo)));
      return true;
    }
    if (name === 'list_repositories') {
      const mine = [...repos.values()].filter((r) => r.owner === VIEWER.login).map((r) => repoShape(r));
      ok(mcpToolResult(mine));
      return true;
    }
    if (name === 'get_repo') {
      const repo = getR();
      if (!repo || o2 !== VIEWER.login) { ok(mcpToolResult(`Repository ${o2}/${n2} not found`, true)); return true; }
      ok(mcpToolResult(repoShape(repo)));
      return true;
    }
    if (name === 'create_issue') {
      const repo = getR();
      if (!repo || o2 !== VIEWER.login) { ok(mcpToolResult(`Repository ${o2}/${n2} not found`, true)); return true; }
      const number = repo.nextNumber; repo.nextNumber += 1;
      const issue: Issue = { number, globalId: globalId('issue', repo.id, number), title: String(args.title ?? ''), body: typeof args.body === 'string' ? args.body : '', state: 'open', labels: [], author: VIEWER.login, createdSeq: nextSeq(), createdAt: nowIso(), updatedAt: nowIso(), comments: [] };
      repo.issues.push(issue);
      repo.updatedAt = nowIso(); repo.version += 1;
      ok(mcpToolResult(issueShape(repo, issue)));
      return true;
    }
    if (name === 'list_issues') {
      const repo = getR();
      if (!repo || o2 !== VIEWER.login) { ok(mcpToolResult(`Repository ${o2}/${n2} not found`, true)); return true; }
      const state = String(args.state ?? 'open');
      const list = repo.issues.filter((i) => state === 'all' || i.state === state).map((i) => issueShape(repo, i));
      ok(mcpToolResult(list));
      return true;
    }
    if (name === 'create_pull_request') {
      const repo = getR();
      if (!repo || o2 !== VIEWER.login) { ok(mcpToolResult(`Repository ${o2}/${n2} not found`, true)); return true; }
      const head = String(args.head ?? '');
      const base = String(args.base ?? repo.defaultBranch);
      const headSha = repo.refs.get(`refs/heads/${head}`);
      const baseSha = repo.refs.get(`refs/heads/${base}`);
      if (!headSha || !baseSha) { ok(mcpToolResult('head or base branch does not exist', true)); return true; }
      const number = repo.nextNumber; repo.nextNumber += 1;
      const pull: Pull = { number, globalId: globalId('pr', repo.id, number), title: String(args.title ?? ''), body: typeof args.body === 'string' ? args.body : '', headRef: head, headSha, baseRef: base, baseSha, state: 'open', merged: false, mergedAt: null, mergeCommitSha: null, createdSeq: nextSeq(), createdAt: nowIso(), updatedAt: nowIso() };
      repo.pulls.push(pull);
      repo.version += 1;
      ok(mcpToolResult(pullShape(repo, pull)));
      return true;
    }
    if (name === 'merge_pull_request') {
      const repo = getR();
      if (!repo || o2 !== VIEWER.login) { ok(mcpToolResult(`Repository ${o2}/${n2} not found`, true)); return true; }
      const num = Number(args.pull_number ?? args.number ?? 0);
      const pull = repo.pulls.find((p) => p.number === num);
      if (!pull) { ok(mcpToolResult(`Pull request #${num} not found`, true)); return true; }
      if (pull.merged) { ok(mcpToolResult('Pull request is already merged', true)); return true; }
      if (mergeableOf(repo, pull) === 'CONFLICTING') { ok(mcpToolResult('Merge conflict', true)); return true; }
      const headInfo = commitOf(repo, pull.headSha);
      if (!headInfo) { ok(mcpToolResult('head commit missing', true)); return true; }
      const mergeCommit = buildCommit(headInfo.tree, [baseTipSha(repo, pull)], `${pull.title} (#${pull.number})`);
      repo.objects.set(mergeCommit.sha, { type: 'commit', data: mergeCommit.data });
      repo.refs.set(`refs/heads/${pull.baseRef}`, mergeCommit.sha);
      pull.merged = true;
      pull.state = 'closed';
      pull.mergedAt = nowIso();
      pull.mergeCommitSha = mergeCommit.sha;
      pull.updatedAt = nowIso();
      repo.version += 1;
      ok(mcpToolResult({ merged: true, sha: mergeCommit.sha, number: pull.number }));
      return true;
    }
    if (name === 'close_issue') {
      const repo = getR();
      if (!repo || o2 !== VIEWER.login) { ok(mcpToolResult(`Repository ${o2}/${n2} not found`, true)); return true; }
      const num = Number(args.issue_number ?? args.number ?? 0);
      const issue = repo.issues.find((i) => i.number === num);
      if (!issue) { ok(mcpToolResult(`Issue #${num} not found`, true)); return true; }
      issue.state = 'closed';
      issue.updatedAt = nowIso();
      repo.version += 1;
      ok(mcpToolResult(issueShape(repo, issue)));
      return true;
    }
    err(-32602, `Unknown tool: ${name}`);
    return true;
  }
  err(-32601, `Method not found: ${method}`);
  return true;
}

// ---------------------------------------------------------------- git smart HTTP

function sendGit(res: ServerResponse, status: number, contentType: string, body: Buffer): void {
  res.writeHead(status, { 'Content-Type': contentType, 'Content-Length': body.length, 'X-GitHub-Request-Id': requestId() });
  res.end(body);
}
function sidebandPack(pack: Buffer): Buffer {
  const parts: Buffer[] = [];
  const CHUNK = 32768;
  for (let off = 0; off < pack.length; off += CHUNK) {
    const slice = pack.subarray(off, Math.min(off + CHUNK, pack.length));
    const banded = Buffer.concat([Buffer.from([1]), slice]);
    parts.push(pktLine(banded));
  }
  if (pack.length === 0) parts.push(pktLine(Buffer.from([1])));
  parts.push(PKT_FLUSH);
  return Buffer.concat(parts);
}
function tagTarget(r: Repo, sha: string): string | null {
  const obj = r.objects.get(sha);
  if (!obj || obj.type !== 'tag') return null;
  const text = obj.data.toString('utf8');
  const m = /^object ([0-9a-f]{40})$/m.exec(text);
  return m ? m[1] : null;
}
function refAdvertisementLines(r: Repo): string[] {
  const lines: string[] = [];
  const tip = r.refs.get(`refs/heads/${r.defaultBranch}`);
  if (tip) lines.push(`${tip} HEAD`);
  const refs = [...r.refs.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1));
  for (const [name, sha] of refs) {
    lines.push(`${sha} ${name}`);
    const peeled = tagTarget(r, sha);
    if (peeled) lines.push(`${peeled} ${name}^{}`);
  }
  return lines;
}
function gitInfoRefs(req: IncomingMessage, res: ServerResponse, repo: Repo, service: string): void {
  const v2 = (req.headers['git-protocol'] ?? '') === 'version=2';
  const serviceLine = `# service=${service}\n`;
  if (service === 'git-upload-pack' && v2) {
    const body = Buffer.concat([
      pktLine(serviceLine), PKT_FLUSH,
      pktLines(['version 2\n', `agent=${AGENT}\n`, 'ls-refs=unborn\n', 'fetch=shallow wait-for-done\n', 'object-format=sha1\n', 'flush']),
    ]);
    sendGit(res, 200, 'application/x-git-upload-pack-advertisement', body);
    return;
  }
  const caps = service === 'git-upload-pack'
    ? `multi_ack thin-pack side-band side-band-64k ofs-delta shallow agent=${AGENT} symref=HEAD:refs/heads/${repo.defaultBranch}`
    : `report-status side-band-64k delete-refs ofs-delta agent=${AGENT}`;
  const lines = refAdvertisementLines(repo);
  const parts: Buffer[] = [pktLine(serviceLine), PKT_FLUSH];
  if (lines.length === 0) {
    parts.push(pktLine(`${ZERO_OID} capabilities^{}\0${caps}\n`));
  } else {
    lines.forEach((line, idx) => {
      parts.push(pktLine(idx === 0 ? `${line}\0${caps}\n` : `${line}\n`));
    });
  }
  parts.push(PKT_FLUSH);
  sendGit(res, 200, service === 'git-upload-pack' ? 'application/x-git-upload-pack-advertisement' : 'application/x-git-receive-pack-advertisement', Buffer.concat(parts));
}
interface FetchPlan { objects: Map<string, GitObj>; shallow: string[]; unshallow: string[] }
function planFetch(r: Repo, wants: string[], haves: string[], depth: number | null, prevShallow: string[]): FetchPlan {
  // Expand wants: a tag object is delivered itself, and its target commit
  // becomes a tip to walk from. Anything else non-commit is delivered as-is.
  const extraObjects = new Set<string>();
  const commitTips: string[] = [];
  for (const w of wants) {
    let cur = w;
    for (let hops = 0; hops < 10; hops++) {
      const obj = r.objects.get(cur);
      if (!obj) break;
      if (obj.type === 'commit') { commitTips.push(cur); break; }
      if (obj.type === 'tag') {
        extraObjects.add(cur);
        const target = tagTarget(r, cur);
        if (!target) break;
        cur = target;
        continue;
      }
      extraObjects.add(cur);
      break;
    }
  }
  // BFS from the tips with depth tracking. A commit is included while its
  // depth is < the limit; the deepest included level (depth == limit - 1) is
  // the shallow boundary — its parents are cut, and IT is named in
  // shallow-info, not the first excluded commit. (Depth 1 therefore carries
  // the tip only, and names the tip as shallow.)
  const queue: Array<{ sha: string; depth: number }> = commitTips.map((w) => ({ sha: w, depth: 0 }));
  const included = new Set<string>();
  const shallowSet = new Set<string>();
  while (queue.length > 0) {
    const cur = queue.shift()!;
    if (included.has(cur.sha) || shallowSet.has(cur.sha)) continue;
    const info = commitOf(r, cur.sha);
    if (!info) continue;
    if (depth !== null && cur.depth >= depth) continue;
    included.add(cur.sha);
    if (depth !== null && cur.depth === depth - 1 && info.parents.length > 0) shallowSet.add(cur.sha);
    for (const p of info.parents) queue.push({ sha: p, depth: cur.depth + 1 });
  }
  // Collect a commit's whole tree (root + subtrees + blobs) into `into`.
  const collectTrees = (rootTree: string, into: Map<string, GitObj>): void => {
    const seen = new Set<string>();
    const stack = [rootTree];
    while (stack.length > 0) {
      const t = stack.pop()!;
      if (seen.has(t)) continue;
      seen.add(t);
      const tobj = r.objects.get(t);
      if (!tobj) continue;
      into.set(t, tobj);
      for (const e of parseTree(tobj.data)) {
        if (e.mode === '40000') stack.push(e.sha);
        else { const b = r.objects.get(e.sha); if (b) into.set(e.sha, b); }
      }
    }
  };
  const objects = new Map<string, GitObj>();
  for (const sha of included) {
    const obj = r.objects.get(sha);
    if (obj) objects.set(sha, obj);
    const info = commitOf(r, sha);
    if (info) collectTrees(info.tree, objects);
  }
  for (const sha of extraObjects) {
    const obj = r.objects.get(sha);
    if (obj) objects.set(sha, obj);
  }
  // Subtract what the client already has: full reachability from haves, except
  // that a shallow boundary in the client's store contributes only itself plus
  // its tree — its parents are NOT in the client's store.
  const prevSet = new Set(prevShallow);
  const haveObjs = new Map<string, GitObj>();
  const hstack: string[] = [...haves];
  const hseen = new Set<string>();
  while (hstack.length > 0) {
    const sha = hstack.pop()!;
    if (hseen.has(sha)) continue;
    hseen.add(sha);
    const obj = r.objects.get(sha);
    if (obj) haveObjs.set(sha, obj);
    const info = commitOf(r, sha);
    if (!info) continue;
    collectTrees(info.tree, haveObjs);
    if (!prevSet.has(sha)) for (const p of info.parents) hstack.push(p);
  }
  for (const sha of haveObjs.keys()) objects.delete(sha);
  const unshallow: string[] = [];
  for (const s of prevShallow) {
    if (included.has(s) && !shallowSet.has(s)) unshallow.push(s);
  }
  return { objects, shallow: [...shallowSet], unshallow };
}
function wantedRefName(r: Repo, sha: string): string {
  for (const [name, tip] of r.refs) if (tip === sha) return name;
  return 'HEAD';
}
async function gitUploadPack(req: IncomingMessage, res: ServerResponse, repo: Repo): Promise<void> {
  const raw = await readBody(req);
  const v2 = (req.headers['git-protocol'] ?? '') === 'version=2';
  if (v2) {
    const packets = parsePktLines(raw);
    let command = '';
    const args: string[] = [];
    let afterDelim = false;
    for (const p of packets) {
      if (p.kind === 'delim') { afterDelim = true; continue; }
      if (p.kind === 'flush') break;
      if (p.kind !== 'data') continue;
      const line = p.payload.toString('utf8');
      if (!afterDelim) {
        if (line.startsWith('command=')) command = line.slice(8).trim();
        continue;
      }
      args.push(line);
    }
    if (command === 'ls-refs') {
      let peel = false;
      let symrefs = false;
      let unborn = false;
      const prefixes: string[] = [];
      for (const a of args) {
        const t = a.trim();
        if (t === 'peel') peel = true;
        else if (t === 'symrefs') symrefs = true;
        else if (t === 'unborn') unborn = true;
        else if (t.startsWith('ref-prefix ')) prefixes.push(t.slice(11));
      }
      const keep = (name: string): boolean => prefixes.length === 0 || prefixes.some((p) => name.startsWith(p));
      const out: string[] = [];
      const tip = repo.refs.get(`refs/heads/${repo.defaultBranch}`);
      if (symrefs && keep('HEAD')) {
        if (tip) out.push(`${tip} HEAD symref-target:refs/heads/${repo.defaultBranch}\n`);
        else if (unborn) out.push(`unborn HEAD symref-target:refs/heads/${repo.defaultBranch}\n`);
      }
      const refs = [...repo.refs.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1));
      for (const [name, sha] of refs) {
        if (!keep(name)) continue;
        let line = `${sha} ${name}`;
        if (peel) { const peeled = tagTarget(repo, sha); if (peeled) line += ` peeled:${peeled}`; }
        out.push(`${line}\n`);
      }
      if (unborn && repo.refs.size === 0) {
        // Only the HEAD line: an `unborn refs/heads/main` entry would read as a
        // real advertised ref to a fresh clone.
      }
      res.writeHead(200, { 'Content-Type': 'application/x-git-upload-pack-result', 'X-GitHub-Request-Id': requestId() });
      res.end(Buffer.concat([pktLines(out), PKT_FLUSH]));
      return;
    }
    if (command === 'fetch') {
      const wants: string[] = [];
      const haves: string[] = [];
      const prevShallow: string[] = [];
      let depth: number | null = null;
      for (const a of args) {
        const t = a.trim();
        if (t.startsWith('want ')) wants.push(t.slice(5).trim());
        else if (t.startsWith('have ')) haves.push(t.slice(5).trim());
        else if (t.startsWith('shallow ')) prevShallow.push(t.slice(8).trim());
        else if (t.startsWith('deepen ')) depth = parseInt(t.slice(7).trim(), 10);
      }
      const plan = planFetch(repo, wants, haves, depth, prevShallow);
      const knownHaves = haves.filter((h) => repo.objects.has(h));
      const parts: Buffer[] = [];
      parts.push(pktLine('acknowledgments\n'));
      if (knownHaves.length > 0) {
        for (const h of knownHaves) parts.push(pktLine(`ACK ${h}\n`));
        parts.push(pktLine('ready\n'));
      } else {
        parts.push(pktLine('NAK\n'));
      }
      parts.push(PKT_DELIM);
      if (plan.shallow.length > 0 || plan.unshallow.length > 0) {
        parts.push(pktLine('shallow-info\n'));
        for (const s of plan.shallow) parts.push(pktLine(`shallow ${s}\n`));
        for (const s of plan.unshallow) parts.push(pktLine(`unshallow ${s}\n`));
        parts.push(PKT_DELIM);
      }
      parts.push(pktLine('wanted-refs\n'));
      for (const w of wants) parts.push(pktLine(`${w} ${wantedRefName(repo, w)}\n`));
      parts.push(PKT_DELIM);
      parts.push(pktLine('packfile\n'));
      const pack = writePack([...plan.objects.values()]);
      parts.push(sidebandPack(pack));
      res.writeHead(200, { 'Content-Type': 'application/x-git-upload-pack-result', 'X-GitHub-Request-Id': requestId() });
      res.end(Buffer.concat(parts));
      return;
    }
    sendJson(res, 400, { message: `unknown command ${command}` });
    return;
  }
  // v0: section 1 = wants (+ shallow/deepen) + flush; section 2 = haves + done + flush.
  const packets = parsePktLines(raw);
  const wants: string[] = [];
  const haves: string[] = [];
  const prevShallow: string[] = [];
  let depth: number | null = null;
  let section = 0;
  for (const p of packets) {
    if (p.kind === 'flush') { section += 1; continue; }
    if (p.kind !== 'data') continue;
    const line = p.payload.toString('utf8').trim();
    if (section === 0) {
      if (line.startsWith('want ')) wants.push(line.split(' ')[1]);
      else if (line.startsWith('shallow ')) prevShallow.push(line.slice(8).trim());
      else if (line.startsWith('deepen ')) depth = parseInt(line.slice(7).trim(), 10);
    } else {
      if (line.startsWith('have ')) haves.push(line.slice(5).trim());
    }
  }
  const plan = planFetch(repo, wants, haves, depth, prevShallow);
  const knownHaves = haves.filter((h) => repo.objects.has(h));
  const parts: Buffer[] = [];
  if (knownHaves.length > 0) for (const h of knownHaves) parts.push(pktLine(`ACK ${h}\n`));
  else parts.push(pktLine('NAK\n'));
  for (const s of plan.shallow) parts.push(pktLine(`shallow ${s}\n`));
  for (const s of plan.unshallow) parts.push(pktLine(`unshallow ${s}\n`));
  const pack = writePack([...plan.objects.values()]);
  parts.push(sidebandPack(pack));
  res.writeHead(200, { 'Content-Type': 'application/x-git-upload-pack-result', 'X-GitHub-Request-Id': requestId() });
  res.end(Buffer.concat(parts));
}
async function gitReceivePack(req: IncomingMessage, res: ServerResponse, repo: Repo): Promise<void> {
  const raw = await readBody(req);
  const packets = parsePktLines(raw);
  const commands: Array<{ oldOid: string; newOid: string; ref: string }> = [];
  let packStart = -1;
  let off = 0;
  // Re-walk the raw buffer to find where the pkt-line stream ends (first flush).
  while (off + 4 <= raw.length) {
    const len = parseInt(raw.subarray(off, off + 4).toString('utf8'), 16);
    if (Number.isNaN(len)) break;
    if (len === 0) { packStart = off + 4; break; }
    if (len === 1) { off += 4; continue; }
    if (off + len > raw.length) break;
    const payload = raw.subarray(off + 4, off + len).toString('utf8');
    const nul = payload.indexOf('\0');
    const clean = (nul >= 0 ? payload.slice(0, nul) : payload).trim();
    const parts = clean.split(' ');
    if (parts.length >= 3) commands.push({ oldOid: parts[0], newOid: parts[1], ref: parts[2] });
    off += len;
  }
  void packets;
  // Store the pack's objects (if any) before applying ref updates.
  if (packStart >= 0 && packStart < raw.length) {
    try {
      const { objects } = readPack(raw.subarray(packStart));
      for (const [sha, obj] of objects) repo.objects.set(sha, obj);
    } catch {
      // A pack that does not parse still gets a report; the ref updates below
      // will fail on the missing objects.
    }
  }
  const lines: string[] = ['unpack ok\n'];
  for (const cmd of commands) {
    const current = repo.refs.get(cmd.ref);
    if (!cmd.ref.startsWith('refs/')) {
      lines.push(`ng ${cmd.ref} invalid ref\n`);
      continue;
    }
    if (cmd.newOid === ZERO_OID) {
      // Delete.
      if (!current) { lines.push(`ng ${cmd.ref} remote ref does not exist\n`); continue; }
      if (cmd.oldOid !== ZERO_OID && cmd.oldOid !== current) { lines.push(`ng ${cmd.ref} non-fast-forward\n`); continue; }
      repo.refs.delete(cmd.ref);
      lines.push(`ok ${cmd.ref}\n`);
      continue;
    }
    if (cmd.oldOid === ZERO_OID) {
      // Create.
      if (current) { lines.push(`ng ${cmd.ref} already exists\n`); continue; }
      if (!repo.objects.has(cmd.newOid)) { lines.push(`ng ${cmd.ref} object not found\n`); continue; }
      repo.refs.set(cmd.ref, cmd.newOid);
      lines.push(`ok ${cmd.ref}\n`);
      continue;
    }
    // Update.
    if (!current) { lines.push(`ng ${cmd.ref} remote ref does not exist\n`); continue; }
    if (cmd.oldOid !== current) { lines.push(`ng ${cmd.ref} non-fast-forward\n`); continue; }
    if (!repo.objects.has(cmd.newOid)) { lines.push(`ng ${cmd.ref} object not found\n`); continue; }
    const ancestors = new Set(walkCommits(repo, [cmd.newOid]));
    if (!ancestors.has(cmd.oldOid)) { lines.push(`ng ${cmd.ref} non-fast-forward\n`); continue; }
    repo.refs.set(cmd.ref, cmd.newOid);
    lines.push(`ok ${cmd.ref}\n`);
  }
  if (commands.some((c) => lines.some((l) => l === `ok ${c.ref}\n`))) {
    repo.updatedAt = nowIso();
    repo.pushedAt = nowIso();
    repo.version += 1;
  }
  const body = Buffer.concat([...lines.map((l) => pktLine(Buffer.concat([Buffer.from([1]), Buffer.from(l, 'utf8')]))), PKT_FLUSH]);
  res.writeHead(200, { 'Content-Type': 'application/x-git-receive-pack-result', 'X-GitHub-Request-Id': requestId() });
  res.end(body);
}
async function handleGit(req: IncomingMessage, res: ServerResponse, path: string, url: URL): Promise<boolean> {
  const m = /^\/([^/]+)\/([^/]+)\.git\/(info\/refs|git-upload-pack|git-receive-pack)$/.exec(path);
  if (!m) return false;
  const owner = decodeURIComponent(m[1]);
  const name = decodeURIComponent(m[2]);
  const action = m[3];
  if (!requireAuth(req, res)) return true;
  const repo = getRepo(owner, name);
  if (!repo || owner !== VIEWER.login) { sendError(res, 404, 'Not Found'); return true; }
  if (action === 'info/refs') {
    const service = url.searchParams.get('service') ?? '';
    if (service !== 'git-upload-pack' && service !== 'git-receive-pack') { sendError(res, 400, 'service is required'); return true; }
    gitInfoRefs(req, res, repo, service);
    return true;
  }
  if (action === 'git-upload-pack') {
    if ((req.method ?? '') !== 'POST') { sendError(res, 405, 'Method Not Allowed'); return true; }
    await gitUploadPack(req, res, repo);
    return true;
  }
  if (action === 'git-receive-pack') {
    if ((req.method ?? '') !== 'POST') { sendError(res, 405, 'Method Not Allowed'); return true; }
    await gitReceivePack(req, res, repo);
    return true;
  }
  return false;
}

// ---------------------------------------------------------------- server + lifecycle

async function postJson(urlStr: string, value: unknown): Promise<{ status: number; text: string }> {
  const res = await fetch(urlStr, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(value) });
  return { status: res.status, text: await res.text() };
}
async function getJson(urlStr: string): Promise<Record<string, unknown>> {
  const res = await fetch(urlStr);
  try { return (await res.json()) as Record<string, unknown>; } catch { return {}; }
}
const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));
async function main(): Promise<void> {
  if (!ENV_URL) {
    process.stderr.write('MAKEFUN_ENV_URL is unset; nothing to register with.\n');
    process.exit(1);
  }
  const server = createServer(async (req, res) => {
    try {
      const url = new URL(req.url ?? '/', 'http://127.0.0.1');
      const path = url.pathname.replace(/\/+$/, '') || '/';
      if (path === '/healthz' && (req.method ?? 'GET') === 'GET') {
        sendJson(res, 200, { ok: true });
        return;
      }
      if (path === '/api/graphql' && (req.method ?? '') === 'POST') {
        await handleGraphql(req, res);
        return;
      }
      if (path === '/mcp' && (req.method ?? '') === 'POST') {
        await handleMcp(req, res);
        return;
      }
      if (path === '/api/v3' || path.startsWith('/api/v3/')) {
        const handled = await handleRest(req, res, path.slice('/api/v3'.length) || '/', url);
        if (handled) return;
      }
      if (await handleGit(req, res, path, url)) return;
      sendError(res, 404, 'Not Found');
    } catch (e) {
      try { sendError(res, 500, e instanceof Error ? e.message : 'Internal Server Error'); } catch { /* socket gone */ }
    }
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
  const address = server.address();
  const port = typeof address === 'object' && address !== null ? address.port : 0;
  // Register with retries; the first register wins.
  let registered = false;
  for (let attempt = 0; attempt < 12 && !registered; attempt += 1) {
    try {
      const r = await postJson(`${ENV_URL.replace(/\/+$/, '')}/register`, { port });
      if (r.status === 200 || r.status === 201 || r.status === 409) registered = true;
    } catch { /* retry */ }
    if (!registered) await sleep(250 * (attempt + 1));
  }
  if (!registered) {
    process.stderr.write('register failed; exiting.\n');
    server.close();
    process.exit(1);
  }
  // Poll /done until the suite's export is written.
  for (;;) {
    await sleep(250);
    try {
      const done = await getJson(`${ENV_URL.replace(/\/+$/, '')}/done`);
      if (done.done === true) break;
    } catch { /* keep polling */ }
  }
  server.close();
  process.exit(0);
}
void main();
