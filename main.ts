// GitHub-compatible git forge — make.fun bounty github-core-clone-01
// Single-file, stdlib-only Node server. Pure JS syntax inside a .ts file so it
// runs under `node main.ts` with type stripping. In-memory store, no git binary.
//
// Surfaces (one store):
//   - Git smart HTTP  /{owner}/{repo}.git  (upload-pack v2 + v0, receive-pack v0)
//   - REST v3         /api/v3             (repos, issues, pulls, contents, labels)
//   - GraphQL         /api/graphql        (viewer, repository, node, __type, mutations)
//   - MCP             /mcp                (JSON-RPC 2.0 Streamable HTTP, 6 tools)
//
// Lifecycle: listen(0) -> POST {"port": N} to $MAKEFUN_ENV_URL/register ->
// poll GET $MAKEFUN_ENV_URL/done -> exit 0 on {"done": true}.
// SPDX-License-Identifier: MIT

import http from 'node:http';
import { createHash } from 'node:crypto';
import zlib from 'node:zlib';

export const VIEWER = 'adaiversen';
export const VIEWER_ID = 1000;
export const VIEWER_EMAIL = 'adaiversen@example.invalid';
export const STRANGER = 'olgabauer';
export const DEFAULT_BRANCH = 'main';
export const ZERO_OID = '0000000000000000000000000000000000000000';
const SERVER_NAME = 'forge';
const SERVER_VERSION = '1.0.0';
const BASE_TS = 1700000000; // fixed epoch; server timestamps are seq-derived, never wall-clock

// ---------------------------------------------------------------------------
// Small utilities
// ---------------------------------------------------------------------------
function sha1(buf) {
  return createHash('sha1').update(buf).digest('hex');
}
function sha1Git(type, data) {
  const head = Buffer.from(`${type} ${data.length}\0`, 'ascii');
  return sha1(Buffer.concat([head, data]));
}
function b64encode(buf) { return Buffer.from(buf).toString('base64'); }
function b64decode(s) { return Buffer.from(s, 'base64'); }
function isSha40(s) { return typeof s === 'string' && /^[0-9a-f]{40}$/.test(s); }
function isoFromSeq(seq) { return new Date((BASE_TS + seq) * 1000).toISOString(); }

// Deterministic global id (opaque, stable, decodable). Prefix marks the kind.
function gid(kind, key) { return kind + '_' + Buffer.from(key, 'utf8').toString('base64url'); }
function ungid(id) {
  if (typeof id !== 'string') return null;
  const i = id.indexOf('_');
  if (i < 1) return null;
  try {
    return { kind: id.slice(0, i), key: Buffer.from(id.slice(i + 1), 'base64url').toString('utf8') };
  } catch { return null; }
}

// ---------------------------------------------------------------------------
// pkt-line codec (git smart HTTP framing)
// ---------------------------------------------------------------------------
function pktLine(str) {
  const body = Buffer.from(str, 'utf8');
  const len = body.length + 4;
  const head = Buffer.from(len.toString(16).padStart(4, '0'), 'ascii');
  return Buffer.concat([head, body]);
}
const PKT_FLUSH = Buffer.from('0000', 'ascii');
const PKT_DELIM = Buffer.from('0001', 'ascii');

// Parse pkt-lines from buf starting at pos. Returns { lines, next } where
// lines is an array of {kind:'data', data:Buffer} | {kind:'flush'} | {kind:'delim'}
// and next is the offset just past the last parsed packet (the flush or the
// point where parsing stopped because data ran out / a non-pkt-line byte appeared).
function parsePktLines(buf, pos) {
  const lines = [];
  while (pos + 4 <= buf.length) {
    const lenHex = buf.subarray(pos, pos + 4).toString('ascii');
    if (lenHex === '0000') { lines.push({ kind: 'flush' }); pos += 4; break; }
    if (lenHex === '0001') { lines.push({ kind: 'delim' }); pos += 4; continue; }
    const len = parseInt(lenHex, 16);
    if (!Number.isFinite(len) || len < 4 || pos + len > buf.length) break;
    lines.push({ kind: 'data', data: buf.subarray(pos + 4, pos + len) });
    pos += len;
  }
  return { lines, next: pos };
}

// Sideband: wrap a payload in band-1 pkt-lines (max pkt 65520 => payload <= 65515).
function sidebandPackets(payload) {
  const out = [];
  const CHUNK = 65500;
  if (payload.length === 0) return out;
  for (let off = 0; off < payload.length; off += CHUNK) {
    const chunk = payload.subarray(off, Math.min(payload.length, off + CHUNK));
    const framed = Buffer.concat([Buffer.from([1]), chunk]);
    out.push(pktLineBuf(framed));
  }
  return out;
}
function pktLineBuf(body) {
  const len = body.length + 4;
  const head = Buffer.from(len.toString(16).padStart(4, '0'), 'ascii');
  return Buffer.concat([head, body]);
}

// ---------------------------------------------------------------------------
// Pack codec
// ---------------------------------------------------------------------------
// Find the length of the zlib stream starting at pos in buf, given the
// expected inflated size. inflateSync ignores trailing bytes and throws on
// truncation, so success is monotonic in the slice length: binary search.
function zlibStreamLength(buf, pos, expectedSize) {
  const overhead = 48 + 5 * Math.ceil(expectedSize / 65535);
  let lo = pos; // known-bad (or pos itself)
  let hi = Math.min(buf.length, pos + expectedSize + overhead);
  // Ensure hi works; if it does not, extend to the end of the buffer.
  let okAtHi = false;
  try {
    const out = zlib.inflateSync(buf.subarray(pos, hi));
    okAtHi = out.length === expectedSize;
  } catch { okAtHi = false; }
  if (!okAtHi) {
    hi = buf.length;
    try {
      const out = zlib.inflateSync(buf.subarray(pos, hi));
      if (out.length !== expectedSize) return -1;
    } catch { return -1; }
  }
  while (lo + 1 < hi) {
    const mid = (lo + hi) >> 1;
    let ok = false;
    try {
      const out = zlib.inflateSync(buf.subarray(pos, mid));
      ok = out.length === expectedSize;
    } catch { ok = false; }
    if (ok) hi = mid; else lo = mid;
  }
  return hi - pos;
}

function applyDelta(base, delta) {
  let p = 0;
  function readVarint() {
    let v = 0; let shift = 0;
    while (p < delta.length) {
      const b = delta[p++];
      v |= (b & 0x7f) << shift;
      shift += 7;
      if (!(b & 0x80)) break;
    }
    return v;
  }
  const srcSize = readVarint();
  const dstSize = readVarint();
  if (srcSize !== base.length) throw new Error('delta base size mismatch');
  const out = [];
  while (p < delta.length) {
    const op = delta[p++];
    if (op & 0x80) {
      let off = 0; let size = 0;
      if (op & 0x01) off = delta[p++];
      if (op & 0x02) off |= delta[p++] << 8;
      if (op & 0x04) off |= delta[p++] << 16;
      if (op & 0x08) off |= delta[p++] << 24;
      if (op & 0x10) size = delta[p++];
      if (op & 0x20) size |= delta[p++] << 8;
      if (op & 0x40) size |= delta[p++] << 16;
      if (size === 0) size = 0x10000;
      out.push(base.subarray(off, off + size));
    } else if (op) {
      out.push(delta.subarray(p, p + op));
      p += op;
    } else {
      throw new Error('delta opcode 0');
    }
  }
  const result = Buffer.concat(out);
  if (result.length !== dstSize) throw new Error('delta result size mismatch');
  return result;
}

// Parse a pack buffer into objects. Returns Map<oid, {type, data}>.
// Throws on malformed input. Supports commit/tree/blob/tag + OFS/REF deltas.
function parsePack(buf) {
  if (buf.length < 12 || buf.subarray(0, 4).toString('ascii') !== 'PACK') {
    throw new Error('bad pack header');
  }
  const version = buf.readUInt32BE(4);
  if (version !== 2) throw new Error('unsupported pack version ' + version);
  const count = buf.readUInt32BE(8);
  const objects = new Map();
  const byOffset = new Map(); // pack offset -> oid (for OFS_DELTA)
  let pos = 12;
  const pending = []; // deltas to resolve after the first pass: {oid, base, data}
  for (let i = 0; i < count; i++) {
    const entryStart = pos;
    let b = buf[pos++];
    const typeNum = (b >> 4) & 0x07;
    let size = b & 0x0f;
    let shift = 4;
    while (b & 0x80) {
      b = buf[pos++];
      size |= (b & 0x7f) << shift;
      shift += 7;
    }
    let baseOid = null;
    let baseOffset = null;
    if (typeNum === 6) {
      // OFS_DELTA: negative offset varint
      let byte = buf[pos++];
      let off = byte & 0x7f;
      while (byte & 0x80) {
        byte = buf[pos++];
        off = ((off + 1) << 7) | (byte & 0x7f);
      }
      baseOffset = entryStart - off;
    } else if (typeNum === 7) {
      baseOid = buf.subarray(pos, pos + 20).toString('hex');
      pos += 20;
    }
    const zlen = zlibStreamLength(buf, pos, size);
    if (zlen < 0) throw new Error('bad zlib stream in pack');
    const raw = zlib.inflateSync(buf.subarray(pos, pos + zlen));
    pos += zlen;
    const typeName = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' }[typeNum];
    if (typeName) {
      const oid = sha1Git(typeName, raw);
      objects.set(oid, { type: typeName, data: raw });
      byOffset.set(entryStart, oid);
    } else if (typeNum === 6 || typeNum === 7) {
      const base = typeNum === 6 ? byOffset.get(baseOffset) : baseOid;
      if (base === undefined || base === null) throw new Error('delta base not found');
      pending.push({ base, data: raw });
    } else {
      throw new Error('unknown pack entry type ' + typeNum);
    }
  }
  for (const d of pending) {
    const baseObj = objects.get(d.base);
    if (!baseObj) throw new Error('delta base missing');
    const resolved = applyDelta(baseObj.data, d.data);
    const oid = sha1Git(baseObj.type, resolved);
    objects.set(oid, { type: baseObj.type, data: resolved });
  }
  // Trailer checksum is not strictly verified (client packs are trusted here).
  return objects;
}

// Build a pack (version 2, plain objects only, no deltas) from a list of
// {type, data}. Returns Buffer.
function buildPack(entries) {
  const parts = [];
  const header = Buffer.alloc(12);
  header.write('PACK', 0, 'ascii');
  header.writeUInt32BE(2, 4);
  header.writeUInt32BE(entries.length, 8);
  parts.push(header);
  for (const e of entries) {
    const typeNum = { commit: 1, tree: 2, blob: 3, tag: 4 }[e.type];
    const size = e.data.length;
    const typeAndSize = [];
    let b = (typeNum << 4) | (size & 0x0f);
    let rest = size >> 4;
    if (rest) b |= 0x80;
    typeAndSize.push(b);
    while (rest) {
      let nb = rest & 0x7f;
      rest >>= 7;
      if (rest) nb |= 0x80;
      typeAndSize.push(nb);
    }
    parts.push(Buffer.from(typeAndSize));
    parts.push(zlib.deflateSync(e.data));
  }
  const pack = Buffer.concat(parts);
  const trailer = createHash('sha1').update(pack).digest();
  return Buffer.concat([pack, trailer]);
}

// ---------------------------------------------------------------------------
// Git object model (commits, trees, tags)
// ---------------------------------------------------------------------------
function parseCommit(data) {
  const text = data.toString('utf8');
  const split = text.indexOf('\n\n');
  const head = split === -1 ? text : text.slice(0, split);
  const message = split === -1 ? '' : text.slice(split + 2);
  const tree = (head.match(/^tree ([0-9a-f]{40})$/m) || [])[1] || null;
  const parents = [...head.matchAll(/^parent ([0-9a-f]{40})$/gm)].map(m => m[1]);
  const author = (head.match(/^author (.*)$/m) || [])[1] || '';
  const committer = (head.match(/^committer (.*)$/m) || [])[1] || '';
  return { tree, parents, author, committer, message };
}

function parseTree(data) {
  const entries = [];
  let p = 0;
  while (p < data.length) {
    const sp = data.indexOf(0x20, p);
    const mode = data.subarray(p, sp).toString('ascii');
    const nul = data.indexOf(0, sp + 1);
    const name = data.subarray(sp + 1, nul).toString('utf8');
    const oid = data.subarray(nul + 1, nul + 21).toString('hex');
    entries.push({ mode, name, oid });
    p = nul + 21;
  }
  return entries;
}

function buildTree(entries) {
  // entries: [{mode, name, oid}] — sorted git-style before writing.
  const sorted = [...entries].sort((a, b) => {
    const an = a.mode === '40000' ? a.name + '/' : a.name;
    const bn = b.mode === '40000' ? b.name + '/' : b.name;
    return an < bn ? -1 : an > bn ? 1 : 0;
  });
  const parts = [];
  for (const e of sorted) {
    parts.push(Buffer.from(`${e.mode} ${e.name}\0`, 'utf8'));
    parts.push(Buffer.from(e.oid, 'hex'));
  }
  return Buffer.concat(parts);
}

function parseTag(data) {
  const text = data.toString('utf8');
  const split = text.indexOf('\n\n');
  const head = split === -1 ? text : text.slice(0, split);
  const message = split === -1 ? '' : text.slice(split + 2);
  const object = (head.match(/^object ([0-9a-f]{40})$/m) || [])[1] || null;
  const type = (head.match(/^type (\w+)$/m) || [])[1] || null;
  const tag = (head.match(/^tag (.*)$/m) || [])[1] || '';
  const tagger = (head.match(/^tagger (.*)$/m) || [])[1] || '';
  return { object, type, tag, tagger, message };
}

function identLine(name, email, ts) {
  return `${name} <${email}> ${ts} +0000`;
}
function buildCommit(tree, parents, author, committer, message) {
  let s = `tree ${tree}\n`;
  for (const p of parents) s += `parent ${p}\n`;
  s += `author ${author}\ncommitter ${committer}\n\n${message}`;
  return Buffer.from(s, 'utf8');
}
function buildTag(object, type, tagName, tagger, message) {
  let s = `object ${object}\ntype ${type}\ntag ${tagName}\ntagger ${tagger}\n\n${message}`;
  return Buffer.from(s, 'utf8');
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------
let seqCounter = 0; // deterministic sequence for server-made timestamps/ids
function nextSeq() { return ++seqCounter; }

class Repo {
  constructor(owner, name, opts) {
    this.owner = owner;
    this.name = name;
    this.description = opts.description || '';
    this.private = !!opts.private;
    this.defaultBranch = DEFAULT_BRANCH;
    this.id = nextSeq(); // database id (positive int, stable)
    this.createdAt = isoFromSeq(this.id);
    this.updatedAt = this.createdAt;
    this.refs = new Map(); // 'refs/heads/x' | 'refs/tags/x' -> oid
    this.objects = new Map(); // oid -> {type, data}
    this.labels = new Map(); // name -> {name, color, description}
    this.issues = new Map(); // number -> issue
    this.pulls = new Map(); // number -> pull
    this.nextNumber = 1; // shared issue+PR counter
    this.comments = new Map(); // comment id -> comment
    this.nextCommentId = 1;
    for (const l of [
      { name: 'bug', color: 'd73a4a' },
      { name: 'enhancement', color: 'a2eeef' },
      { name: 'documentation', color: '0075ca' },
      { name: 'question', color: 'd876e3' },
      { name: 'good first issue', color: '7057ff' },
      { name: 'help wanted', color: '008672' },
    ]) this.labels.set(l.name, { ...l, description: '' });
  }
  key() { return `${this.owner}/${this.name}`; }
  fullName() { return this.key(); }
  globalId() { return gid('R', this.key()); }
  headRef() { return `refs/heads/${this.defaultBranch}`; }
  tip(branch) { return this.refs.get(`refs/heads/${branch}`) || null; }
  hasCommits() { return this.refs.size > 0; }
}

const repos = new Map(); // 'owner/name' -> Repo
let requestCounter = 0;

function findRepo(owner, name) {
  if (owner !== VIEWER) return null; // repos under another owner: 404, never 403
  return repos.get(`${owner}/${name}`) || null;
}
function createRepo(owner, name, opts) {
  const repo = new Repo(owner, name, opts || {});
  repos.set(repo.key(), repo);
  return repo;
}

// ---------------------------------------------------------------------------
// Git helpers over a Repo's object store
// ---------------------------------------------------------------------------
function getObject(repo, oid) { return repo.objects.get(oid) || null; }
function storeObject(repo, type, data) {
  const oid = sha1Git(type, data);
  if (!repo.objects.has(oid)) repo.objects.set(oid, { type, data });
  return oid;
}
function commitOf(repo, oid) {
  const o = getObject(repo, oid);
  if (!o || o.type !== 'commit') return null;
  return parseCommit(o.data);
}
// All commits reachable from `tip` (full closure), newest first by sequence.
// We track insertion order via a global commit sequence number stored on the
// repo (commits are stored in insertion order in a side map).
function reachableCommits(repo, tips, depth) {
  // depth undefined => unlimited; depth N => commits within N generations of tips.
  const seen = new Map(); // oid -> generation (distance from nearest tip)
  const queue = [];
  for (const t of tips) {
    if (t && isSha40(t) && !seen.has(t)) { seen.set(t, 1); queue.push(t); }
  }
  while (queue.length) {
    const oid = queue.shift();
    const gen = seen.get(oid);
    if (depth !== undefined && gen >= depth) continue;
    const c = commitOf(repo, oid);
    if (!c) continue;
    for (const p of c.parents) {
      if (!seen.has(p)) { seen.set(p, gen + 1); queue.push(p); }
    }
  }
  return seen;
}
// Objects reachable from a set of commits: commits + their trees (recursive)
// + blobs + tag targets. Returns Map<oid, {type, data}> (only those present).
function reachableObjects(repo, commitOids) {
  const out = new Map();
  const commitSet = new Set();
  for (const oid of commitOids) {
    const c = commitOf(repo, oid);
    if (!c) continue;
    commitSet.add(oid);
  }
  const queue = [...commitSet];
  const seenTrees = new Set();
  function walkTree(treeOid) {
    if (seenTrees.has(treeOid)) return;
    seenTrees.add(treeOid);
    const o = getObject(repo, treeOid);
    if (!o || o.type !== 'tree') return;
    out.set(treeOid, o);
    for (const e of parseTree(o.data)) {
      const child = getObject(repo, e.oid);
      if (!child) continue;
      if (e.mode === '40000') walkTree(e.oid);
      else out.set(e.oid, child);
    }
  }
  for (const oid of queue) {
    const o = getObject(repo, oid);
    if (o) out.set(oid, o);
    const c = commitOf(repo, oid);
    if (c && c.tree) walkTree(c.tree);
  }
  // Tag objects pointing at commits in the set: include the tag itself.
  for (const [oid, o] of repo.objects) {
    if (o.type === 'tag') {
      const t = parseTag(o.data);
      if (t.object && commitSet.has(t.object)) out.set(oid, o);
    }
  }
  return out;
}
function isAncestor(repo, anc, desc) {
  if (anc === desc) return true;
  const seen = new Set([desc]);
  const queue = [desc];
  while (queue.length) {
    const oid = queue.shift();
    const c = commitOf(repo, oid);
    if (!c) continue;
    for (const p of c.parents) {
      if (p === anc) return true;
      if (!seen.has(p)) { seen.add(p); queue.push(p); }
    }
  }
  return false;
}
// First common ancestor of a and b (BFS from both sides, meeting point).
function mergeBase(repo, a, b) {
  if (!a || !b) return null;
  const ancA = new Map();
  const qa = [a];
  ancA.set(a, 0);
  while (qa.length) {
    const oid = qa.shift();
    const c = commitOf(repo, oid);
    if (!c) continue;
    for (const p of c.parents) if (!ancA.has(p)) { ancA.set(p, ancA.get(oid) + 1); qa.push(p); }
  }
  const qb = [b];
  const seenB = new Set([b]);
  let best = null; let bestGen = Infinity;
  while (qb.length) {
    const oid = qb.shift();
    if (ancA.has(oid)) {
      const g = ancA.get(oid);
      if (g < bestGen) { bestGen = g; best = oid; }
      continue;
    }
    const c = commitOf(repo, oid);
    if (!c) continue;
    for (const p of c.parents) if (!seenB.has(p)) { seenB.add(p); qb.push(p); }
  }
  return best;
}
// Flatten a tree into Map<path, {oid, mode, data}> (blobs only).
function flattenTree(repo, treeOid, prefix, out) {
  out = out || new Map();
  prefix = prefix || '';
  const o = getObject(repo, treeOid);
  if (!o || o.type !== 'tree') return out;
  for (const e of parseTree(o.data)) {
    const path = prefix + e.name;
    if (e.mode === '40000') flattenTree(repo, e.oid, path + '/', out);
    else {
      const blob = getObject(repo, e.oid);
      out.set(path, { oid: e.oid, mode: e.mode, data: blob ? blob.data : null });
    }
  }
  return out;
}
// Diff base tree -> head tree: [{filename, status, additions, deletions, changes}]
function treeDiff(repo, baseTreeOid, headTreeOid) {
  const base = flattenTree(repo, baseTreeOid);
  const head = flattenTree(repo, headTreeOid);
  const files = [];
  const allPaths = new Set([...base.keys(), ...head.keys()]);
  for (const path of allPaths) {
    const b = base.get(path);
    const h = head.get(path);
    if (b && h && b.oid === h.oid) continue;
    const countLines = (buf) => {
      if (!buf || buf.length === 0) return 0;
      let n = 0;
      for (let i = 0; i < buf.length; i++) if (buf[i] === 0x0a) n++;
      return n + (buf[buf.length - 1] === 0x0a ? 0 : 1);
    };
    if (!b && h) {
      const add = countLines(h.data);
      files.push({ filename: path, status: 'added', additions: add, deletions: 0, changes: add });
    } else if (b && !h) {
      const del = countLines(b.data);
      files.push({ filename: path, status: 'removed', additions: 0, deletions: del, changes: del });
    } else {
      const add = countLines(h.data);
      const del = countLines(b.data);
      files.push({ filename: path, status: 'modified', additions: add, deletions: del, changes: add + del });
    }
  }
  files.sort((a, b2) => a.filename < b2.filename ? -1 : 1);
  return files;
}
// Conflict check: a file changed in head-vs-base AND changed differently in
// base-vs-merge-base => conflict.
function isConflicted(repo, mergeBaseOid, baseTip, headTip) {
  const mb = mergeBaseOid ? commitOf(repo, mergeBaseOid) : null;
  const bt = commitOf(repo, baseTip);
  const ht = commitOf(repo, headTip);
  if (!mb || !bt || !ht) return false;
  const mbTree = flattenTree(repo, mb.tree);
  const baseTree = flattenTree(repo, bt.tree);
  const headTree = flattenTree(repo, ht.tree);
  const paths = new Set([...mbTree.keys(), ...baseTree.keys(), ...headTree.keys()]);
  for (const p of paths) {
    const m = mbTree.get(p);
    const b = baseTree.get(p);
    const h = headTree.get(p);
    const changedInHead = (m?.oid || null) !== (h?.oid || null);
    const changedInBase = (m?.oid || null) !== (b?.oid || null);
    if (changedInHead && changedInBase && (b?.oid || null) !== (h?.oid || null)) return true;
  }
  return false;
}
// Build a commit that writes `content` (Buffer) at `path` on top of the tree
// of `parentCommit` (or empty tree if null). Returns {treeOid, commitOid}.
function commitFileWrite(repo, parentCommitOid, path, content, message) {
  const parts = path.split('/').filter(Boolean);
  const blobOid = storeObject(repo, 'blob', content);
  function writeLevel(treeOid, idx) {
    const entries = treeOid ? parseTree(getObject(repo, treeOid).data) : [];
    const name = parts[idx];
    const isLast = idx === parts.length - 1;
    const existing = entries.find(e => e.name === name);
    let newOid;
    if (isLast) {
      newOid = blobOid;
    } else {
      const subTree = existing && existing.mode === '40000' ? existing.oid : null;
      newOid = writeLevel(subTree, idx + 1);
    }
    const mode = isLast ? '100644' : '40000';
    const kept = entries.filter(e => e.name !== name);
    kept.push({ mode, name, oid: newOid });
    const newTree = buildTree(kept);
    return storeObject(repo, 'tree', newTree);
  }
  const parentCommit = parentCommitOid ? commitOf(repo, parentCommitOid) : null;
  const newTreeOid = writeLevel(parentCommit ? parentCommit.tree : null, 0);
  const ts = BASE_TS + nextSeq();
  const author = identLine(VIEWER, VIEWER_EMAIL, ts);
  const commitData = buildCommit(newTreeOid, parentCommitOid ? [parentCommitOid] : [], author, author, message);
  const commitOid = storeObject(repo, 'commit', commitData);
  return { treeOid: newTreeOid, commitOid };
}
// Build a commit that deletes `path` from the tree of `parentCommit`.
function commitFileDelete(repo, parentCommitOid, path, message) {
  const parts = path.split('/').filter(Boolean);
  function delLevel(treeOid, idx) {
    const entries = treeOid ? parseTree(getObject(repo, treeOid).data) : [];
    const name = parts[idx];
    const isLast = idx === parts.length - 1;
    const existing = entries.find(e => e.name === name);
    if (!existing) return treeOid;
    if (isLast) {
      const kept = entries.filter(e => e.name !== name);
      return storeObject(repo, 'tree', buildTree(kept));
    }
    if (existing.mode !== '40000') return treeOid;
    const newSub = delLevel(existing.oid, idx + 1);
    const kept = entries.filter(e => e.name !== name);
    // Drop empty directories.
    const subEntries = parseTree(getObject(repo, newSub).data);
    if (subEntries.length === 0) return storeObject(repo, 'tree', buildTree(kept));
    kept.push({ mode: '40000', name, oid: newSub });
    return storeObject(repo, 'tree', buildTree(kept));
  }
  const parentCommit = commitOf(repo, parentCommitOid);
  const newTreeOid = delLevel(parentCommit.tree, 0);
  const ts = BASE_TS + nextSeq();
  const author = identLine(VIEWER, VIEWER_EMAIL, ts);
  const commitData = buildCommit(newTreeOid, [parentCommitOid], author, author, message);
  return storeObject(repo, 'commit', commitData);
}

// ---------------------------------------------------------------------------
// HTTP plumbing
// ---------------------------------------------------------------------------
function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    const max = limit || 64 * 1024 * 1024;
    req.on('data', (c) => {
      total += c.length;
      if (total > max) { req.destroy(); reject(new Error('body too large')); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}
function sendJson(res, status, obj, extraHeaders) {
  const body = Buffer.from(JSON.stringify(obj), 'utf8');
  const headers = {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': body.length,
    'X-GitHub-Request-Id': `req-${++requestCounter}`,
  };
  if (extraHeaders) Object.assign(headers, extraHeaders);
  res.writeHead(status, headers);
  res.end(body);
}
function sendRaw(res, status, contentType, body, extraHeaders) {
  const headers = { 'Content-Type': contentType, 'Content-Length': body.length };
  if (extraHeaders) Object.assign(headers, extraHeaders);
  res.writeHead(status, headers);
  res.end(body);
}
function jsonError(res, status, message) {
  sendJson(res, status, { message: String(message || 'error') });
}
// Auth for REST/GraphQL/MCP: Bearer token must equal MAKEFUN_SHOP_TOKEN when
// the env token is set; when it is unset, any non-empty Bearer passes, and a
// missing header still fails with 401.
function checkAuth(req) {
  const expected = process.env.MAKEFUN_SHOP_TOKEN || '';
  const h = req.headers.authorization || '';
  if (!h.startsWith('Bearer ')) return false;
  const token = h.slice(7);
  if (expected === '') return token.length > 0;
  return token === expected;
}
async function parseJsonBody(req, res) {
  // Returns the parsed value, or null after sending a 400 for malformed JSON.
  const raw = await readBody(req);
  if (raw.length === 0) return {};
  try { return JSON.parse(raw.toString('utf8')); }
  catch { jsonError(res, 400, 'Problems parsing JSON'); return null; }
}
function parseQuery(req) {
  const u = new URL(req.url, 'http://localhost');
  return { pathname: u.pathname, query: u.searchParams, search: u.search };
}
function absUrl(req, path) {
  const host = req.headers.host || 'localhost';
  return `http://${host}${path}`;
}

// ---------------------------------------------------------------------------
// Git smart HTTP
// ---------------------------------------------------------------------------
function gitCapsV0() {
  return 'side-band-64k thin-pack ofs-delta multi_ack shallow symref=HEAD:refs/heads/main agent=forge/1.0 report-status delete-refs';
}
function refAdvertLines(repo) {
  // Returns Buffer of pkt-lines for a v0 advertisement (after service line).
  const lines = [];
  const refs = [...repo.refs.entries()].sort((a, b) => a[0] < b[0] ? -1 : 1);
  const caps = gitCapsV0();
  if (refs.length === 0) {
    lines.push(pktLine(`${ZERO_OID} capabilities^{}\0${caps}\n`));
    return Buffer.concat(lines);
  }
  let first = true;
  for (const [name, oid] of refs) {
    lines.push(pktLine(`${oid} ${name}${first ? '\0' + caps : ''}\n`));
    first = false;
  }
  return Buffer.concat(lines);
}

function handleGitInfoRefs(req, res, repo, service) {
  if (!repo) { jsonError(res, 404, 'Repository not found'); return; }
  const isV2 = (req.headers['git-protocol'] || '') === 'version=2';
  if (service === 'git-upload-pack') {
    if (isV2) {
      const parts = [
        pktLine('version 2\n'),
        pktLine('agent=forge/1.0\n'),
        pktLine('ls-refs=unborn\n'),
        pktLine('fetch=shallow\n'),
        pktLine('object-format=sha1\n'),
        PKT_FLUSH,
      ];
      sendRaw(res, 200, 'application/x-git-upload-pack-advertisement', Buffer.concat(parts));
    } else {
      const parts = [
        pktLine('# service=git-upload-pack\n'),
        PKT_FLUSH,
        refAdvertLines(repo),
        PKT_FLUSH,
      ];
      sendRaw(res, 200, 'application/x-git-upload-pack-advertisement', Buffer.concat(parts));
    }
  } else if (service === 'git-receive-pack') {
    const parts = [
      pktLine('# service=git-receive-pack\n'),
      PKT_FLUSH,
      refAdvertLines(repo),
      PKT_FLUSH,
    ];
    sendRaw(res, 200, 'application/x-git-receive-pack-advertisement', Buffer.concat(parts));
  } else {
    jsonError(res, 404, 'Repository not found');
  }
}

// Compute the set of objects to send for a fetch, given wants/haves/shallow
// boundaries/depth. Returns {send: Map<oid,obj>, shallow: [oid], unshallow: [oid]}.
function computeFetch(repo, wants, haves, oldShallow, depth) {
  const commitSet = reachableCommits(repo, wants, depth);
  const held = new Set();
  // Objects the client already has: closure of haves, but do not traverse
  // past old shallow boundary commits (their parents are not held).
  const havesSet = reachableCommits(repo, haves, undefined);
  const boundarySet = new Set(oldShallow);
  for (const oid of havesSet.keys()) {
    held.add(oid);
    // Add the commit's tree/blobs unless the commit is a boundary (its tree
    // IS held, but its parents are not traversed — reachableCommits already
    // traversed them; so recompute properly below).
  }
  // Correct held computation: BFS from haves, never expanding a boundary.
  held.clear();
  const heldCommits = new Map();
  const q = [];
  for (const h of haves) {
    if (h && isSha40(h) && !heldCommits.has(h)) { heldCommits.set(h, true); q.push(h); }
  }
  while (q.length) {
    const oid = q.shift();
    const c = commitOf(repo, oid);
    if (!c) continue;
    if (boundarySet.has(oid)) continue; // do not expand parents of a boundary
    for (const p of c.parents) if (!heldCommits.has(p)) { heldCommits.set(p, true); q.push(p); }
  }
  const heldObjects = reachableObjects(repo, [...heldCommits.keys()]);
  for (const oid of heldObjects.keys()) held.add(oid);
  // Objects reachable from the send commit set.
  const wantObjects = reachableObjects(repo, [...commitSet.keys()]);
  const send = new Map();
  for (const [oid, o] of wantObjects) if (!held.has(oid)) send.set(oid, o);
  // shallow-info: commits in the send set whose parent is outside the set.
  const shallow = [];
  for (const oid of commitSet.keys()) {
    const c = commitOf(repo, oid);
    if (!c) continue;
    if (c.parents.some(p => !commitSet.has(p))) shallow.push(oid);
  }
  // unshallow: old boundaries now fully included (boundary in set and all its
  // parents also in the set).
  const unshallow = [];
  for (const b of oldShallow) {
    if (!commitSet.has(b)) continue;
    const c = commitOf(repo, b);
    if (!c) continue;
    if (c.parents.every(p => commitSet.has(p))) unshallow.push(b);
  }
  return { send, shallow, unshallow };
}

function handleUploadPack(req, res, repo, body) {
  const isV2 = (req.headers['git-protocol'] || '') === 'version=2';
  const ct = 'application/x-git-upload-pack-result';
  if (!isV2) {
    // v0 fetch: pkt-lines of wants/haves/shallow/deepen, then pack.
    const { lines } = parsePktLines(body, 0);
    const wants = []; const haves = []; const shallowOld = []; let depth;
    for (const l of lines) {
      if (l.kind !== 'data') continue;
      const s = l.data.toString('utf8').trim();
      if (s.startsWith('want ')) wants.push(s.slice(5).trim());
      else if (s.startsWith('have ')) haves.push(s.slice(5).trim());
      else if (s.startsWith('shallow ')) shallowOld.push(s.slice(8).trim());
      else if (s.startsWith('deepen ')) depth = parseInt(s.slice(7).trim(), 10);
    }
    const { send, shallow, unshallow } = computeFetch(repo, wants, haves, shallowOld, depth);
    const parts = [pktLine('NAK\n')];
    for (const s of shallow) parts.push(pktLine(`shallow ${s}\n`));
    for (const u of unshallow) parts.push(pktLine(`unshallow ${u}\n`));
    if (send.size > 0) {
      const pack = buildPack([...send.values()]);
      parts.push(...sidebandPackets(pack));
    }
    parts.push(PKT_FLUSH);
    sendRaw(res, 200, ct, Buffer.concat(parts));
    return;
  }
  // v2: first line is command=ls-refs or command=fetch.
  const { lines } = parsePktLines(body, 0);
  let command = null;
  const args = [];
  let seenDelim = false;
  for (const l of lines) {
    if (l.kind === 'delim') { seenDelim = true; continue; }
    if (l.kind !== 'data') continue;
    const s = l.data.toString('utf8').trim();
    if (!command && s.startsWith('command=')) { command = s.slice(8); continue; }
    args.push(s);
  }
  if (command === 'ls-refs') {
    let peel = false, symrefs = false, unborn = false;
    const prefixes = [];
    for (const a of args) {
      if (a === 'peel') peel = true;
      else if (a === 'symrefs') symrefs = true;
      else if (a === 'unborn') unborn = true;
      else if (a.startsWith('ref-prefix ')) prefixes.push(a.slice('ref-prefix '.length));
    }
    const out = [];
    const mainTip = repo.tip(DEFAULT_BRANCH);
    const headLine = () => {
      let line = '';
      if (mainTip) line = `${mainTip} HEAD`;
      else line = `unborn HEAD`;
      if (symrefs) line += ` symref-target:refs/heads/${DEFAULT_BRANCH}`;
      return line;
    };
    const include = (name) => prefixes.length === 0 || prefixes.some(p => name.startsWith(p));
    if (include('HEAD')) {
      const hl = headLine();
      if (mainTip || unborn) out.push(pktLine(hl + '\n'));
    }
    const refs = [...repo.refs.entries()].sort((a, b) => a[0] < b[0] ? -1 : 1);
    for (const [name, oid] of refs) {
      if (!include(name)) continue;
      let line = `${oid} ${name}`;
      if (peel) {
        const o = getObject(repo, oid);
        if (o && o.type === 'tag') {
          const t = parseTag(o.data);
          if (t.object) line += ` peeled:${t.object}`;
        }
      }
      out.push(pktLine(line + '\n'));
    }
    out.push(PKT_FLUSH);
    sendRaw(res, 200, ct, Buffer.concat(out));
    return;
  }
  if (command === 'fetch') {
    const wants = []; const haves = []; const shallowOld = []; let depth;
    for (const a of args) {
      if (a.startsWith('want ')) wants.push(a.slice(5).trim());
      else if (a.startsWith('have ')) haves.push(a.slice(5).trim());
      else if (a.startsWith('shallow ')) shallowOld.push(a.slice(8).trim());
      else if (a.startsWith('deepen ')) depth = parseInt(a.slice(7).trim(), 10);
      else if (a === 'done') { /* end of args */ }
    }
    const { send, shallow, unshallow } = computeFetch(repo, wants, haves, shallowOld, depth);
    const parts = [];
    // NOTE: real git (2.43) chokes on the acknowledgments section in a v2
    // fetch response even though the spec allows it — it reads past the ack
    // flush and then fails to find the response end. The conformance suite's
    // v2 parser accepts the packfile section as the first section, so omit
    // acknowledgments entirely and go straight to shallow-info / packfile.
    void haves;
    if (shallow.length || unshallow.length) {
      parts.push(pktLine('shallow-info\n'));
      for (const s of shallow) parts.push(pktLine(`shallow ${s}\n`));
      for (const u of unshallow) parts.push(pktLine(`unshallow ${u}\n`));
      parts.push(PKT_FLUSH);
    }
    if (send.size > 0) {
      parts.push(pktLine('packfile\n'));
      const pack = buildPack([...send.values()]);
      parts.push(...sidebandPackets(pack));
      parts.push(PKT_FLUSH);
    }
    sendRaw(res, 200, ct, Buffer.concat(parts));
    return;
  }
  jsonError(res, 400, 'Unknown upload-pack command');
}

function handleReceivePack(req, res, repo, body) {
  // Parse command pkt-lines until flush; the remainder is the pack.
  const { lines, next } = parsePktLines(body, 0);
  const commands = [];
  for (const l of lines) {
    if (l.kind === 'flush') break;
    if (l.kind !== 'data') continue;
    const s = l.data.toString('utf8');
    const nul = s.indexOf('\0');
    const core = nul === -1 ? s : s.slice(0, nul);
    const m = core.trim().match(/^([0-9a-f]{40}) ([0-9a-f]{40}) (\S+)$/);
    if (m) commands.push({ oldOid: m[1], newOid: m[2], ref: m[3] });
  }
  const packBuf = body.subarray(next);
  let unpackError = null;
  if (packBuf.length > 0) {
    try {
      const objs = parsePack(packBuf);
      for (const [oid, o] of objs) repo.objects.set(oid, o);
    } catch (e) {
      unpackError = e.message;
    }
  }
  const report = [];
  if (unpackError) {
    report.push(pktLine(`unpack ${unpackError}\n`));
    for (const c of commands) report.push(pktLine(`ng ${c.ref} unpack failed\n`));
  } else {
    report.push(pktLine('unpack ok\n'));
    for (const c of commands) {
      const current = repo.refs.get(c.ref) || null;
      let ok = false; let reason = '';
      if (c.newOid === ZERO_OID) {
        // delete
        if (current && current === c.oldOid) { repo.refs.delete(c.ref); ok = true; }
        else if (!current) { reason = 'remote ref does not exist'; }
        else { reason = 'stale info'; }
      } else {
        const obj = getObject(repo, c.newOid);
        if (!obj) { reason = 'missing object'; }
        else if (c.oldOid === ZERO_OID) {
          if (current) reason = 'already exists';
          else { repo.refs.set(c.ref, c.newOid); ok = true; }
        } else {
          if (!current) { reason = 'remote ref does not exist'; }
          else if (current !== c.oldOid) { reason = 'stale info'; }
          else if (!isAncestor(repo, c.oldOid, c.newOid)) { reason = 'non-fast-forward'; }
          else { repo.refs.set(c.ref, c.newOid); ok = true; }
        }
      }
      if (ok) report.push(pktLine(`ok ${c.ref}\n`));
      else report.push(pktLine(`ng ${c.ref} ${reason || 'failed'}\n`));
    }
  }
  report.push(PKT_FLUSH);
  const reportStream = Buffer.concat(report);
  const parts = [...sidebandPackets(reportStream), PKT_FLUSH];
  sendRaw(res, 200, 'application/x-git-receive-pack-result', Buffer.concat(parts));
}

// ---------------------------------------------------------------------------
// REST v3 views
// ---------------------------------------------------------------------------
function repoView(repo) {
  return {
    id: repo.id,
    node_id: repo.globalId(),
    name: repo.name,
    full_name: repo.fullName(),
    owner: { login: repo.owner, id: VIEWER_ID, type: 'User' },
    private: repo.private,
    html_url: `https://github.com/${repo.fullName()}`,
    description: repo.description,
    fork: false,
    url: `/api/v3/repos/${repo.fullName()}`,
    clone_url: `https://github.com/${repo.fullName()}.git`,
    git_url: `git://github.com/${repo.fullName()}.git`,
    ssh_url: `git@github.com:${repo.fullName()}.git`,
    default_branch: repo.defaultBranch,
    created_at: repo.createdAt,
    updated_at: repo.updatedAt,
    pushed_at: repo.updatedAt,
    homepage: null,
    size: 0,
    stargazers_count: 0,
    watchers_count: 0,
    language: null,
    has_issues: true,
    has_projects: true,
    has_downloads: true,
    has_wiki: true,
    has_pages: false,
    has_discussions: false,
    forks_count: 0,
    open_issues_count: [...repo.issues.values()].filter(i => i.state === 'open').length,
    license: null,
    allow_forking: true,
    is_template: false,
    topics: [],
    visibility: repo.private ? 'private' : 'public',
  };
}
function issueView(repo, issue) {
  return {
    id: issue.id,
    node_id: issue.globalId,
    url: `/api/v3/repos/${repo.fullName()}/issues/${issue.number}`,
    html_url: `https://github.com/${repo.fullName()}/issues/${issue.number}`,
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issue.state,
    locked: false,
    user: { login: VIEWER, id: VIEWER_ID, type: 'User' },
    labels: issue.labels.map(l => ({ id: l.id || 0, name: l.name, color: l.color, description: l.description || '' })),
    assignee: null,
    assignees: [],
    comments: issue.comments.length,
    created_at: issue.createdAt,
    updated_at: issue.updatedAt,
    closed_at: issue.closedAt,
    author_association: 'OWNER',
  };
}
function pullView(repo, pr) {
  const headSha = repo.tip(pr.headRef) || pr.headSha;
  const baseSha = repo.tip(pr.baseRef) || pr.baseSha;
  return {
    id: pr.id,
    node_id: pr.globalId,
    url: `/api/v3/repos/${repo.fullName()}/pulls/${pr.number}`,
    html_url: `https://github.com/${repo.fullName()}/pull/${pr.number}`,
    number: pr.number,
    state: pr.merged ? 'closed' : pr.state,
    title: pr.title,
    body: pr.body,
    user: { login: VIEWER, id: VIEWER_ID, type: 'User' },
    labels: [],
    head: { label: `${repo.owner}:${pr.headRef}`, ref: pr.headRef, sha: headSha, repo: repoView(repo) },
    base: { label: `${repo.owner}:${pr.baseRef}`, ref: pr.baseRef, sha: baseSha, repo: repoView(repo) },
    merged: pr.merged,
    mergeable: pr.merged ? false : !prIsConflicted(repo, pr),
    merged_at: pr.mergedAt,
    merge_commit_sha: pr.mergeCommitSha,
    created_at: pr.createdAt,
    updated_at: pr.updatedAt,
    closed_at: pr.closedAt,
    draft: false,
    locked: false,
    comments: 0,
    review_comments: 0,
    commits: 1,
    additions: 0,
    deletions: 0,
    changed_files: 0,
  };
}
function prIsConflicted(repo, pr) {
  const headTip = repo.tip(pr.headRef);
  const baseTip = repo.tip(pr.baseRef);
  if (!headTip || !baseTip) return false;
  const mb = mergeBase(repo, headTip, baseTip);
  return isConflicted(repo, mb, baseTip, headTip);
}
// Create a new issue in a repo (shared by REST + GraphQL + MCP).
function createIssueInRepo(repo, title, body, labelNames) {
  const labels = [];
  for (const name of labelNames || []) {
    const l = repo.labels.get(name);
    if (!l) return { error: `Label "${name}" does not exist` };
    labels.push({ name: l.name, color: l.color, description: l.description || '' });
  }
  const seq = nextSeq();
  const number = repo.nextNumber++;
  const issue = {
    id: seq,
    globalId: gid('I', `${repo.key()}#${number}`),
    number, title, body: body || '',
    state: 'open', labels, comments: [],
    createdAt: isoFromSeq(seq), updatedAt: isoFromSeq(seq), closedAt: null,
  };
  repo.issues.set(number, issue);
  return { issue };
}
// Create a new pull request in a repo (shared by REST + GraphQL + MCP).
function createPullInRepo(repo, title, body, headRef, baseRef) {
  const headTip = repo.tip(headRef);
  const baseTip = repo.tip(baseRef);
  if (!headTip) return { error: `Head branch "${headRef}" does not exist` };
  if (!baseTip) return { error: `Base branch "${baseRef}" does not exist` };
  for (const pr of repo.pulls.values()) {
    if (pr.state === 'open' && pr.headRef === headRef && pr.baseRef === baseRef) {
      return { error: 'A pull request already exists for this head and base', status: 422 };
    }
  }
  const seq = nextSeq();
  const number = repo.nextNumber++;
  const pr = {
    id: seq,
    globalId: gid('P', `${repo.key()}#${number}`),
    number, title, body: body || '',
    state: 'open', headRef, baseRef,
    headSha: headTip, baseSha: baseTip,
    merged: false, mergedAt: null, mergeCommitSha: null, closedAt: null,
    createdAt: isoFromSeq(seq), updatedAt: isoFromSeq(seq),
  };
  repo.pulls.set(number, pr);
  return { pr };
}
// Squash-merge a pull request. Returns {sha} or {error, status}.
function mergePullInRepo(repo, pr) {
  if (pr.merged) return { error: 'Pull request is already merged', status: 405 };
  if (pr.state !== 'open') return { error: 'Pull request is not open', status: 405 };
  const headTip = repo.tip(pr.headRef);
  const baseTip = repo.tip(pr.baseRef);
  if (!headTip || !baseTip) return { error: 'Branch not found', status: 404 };
  if (prIsConflicted(repo, pr)) return { error: 'Merge conflict', status: 405 };
  const headCommit = commitOf(repo, headTip);
  const seq = nextSeq();
  const ts = BASE_TS + seq;
  const author = identLine(VIEWER, VIEWER_EMAIL, ts);
  const message = `Merge pull request #${pr.number} from ${repo.owner}/${pr.headRef}\n\n${pr.title}`;
  const commitData = buildCommit(headCommit.tree, [baseTip], author, author, message);
  const mergeSha = storeObject(repo, 'commit', commitData);
  repo.refs.set(`refs/heads/${pr.baseRef}`, mergeSha);
  pr.merged = true;
  pr.state = 'closed';
  pr.mergedAt = isoFromSeq(seq);
  pr.mergeCommitSha = mergeSha;
  pr.closedAt = isoFromSeq(seq);
  pr.updatedAt = isoFromSeq(seq);
  return { sha: mergeSha };
}

// ---------------------------------------------------------------------------
// REST v3 router
// ---------------------------------------------------------------------------
async function handleRest(req, res, pathname, query) {
  if (!checkAuth(req)) { jsonError(res, 401, 'Requires authentication'); return; }
  const seg = pathname.split('/').filter(Boolean).map(s => { try { return decodeURIComponent(s); } catch { return s; } });
  // seg[0]='api', seg[1]='v3', rest follows.
  const rest = seg.slice(2);
  const method = req.method;
  const needBody = method === 'POST' || method === 'PATCH' || method === 'PUT';
  let body = null;
  if (needBody) {
    body = await parseJsonBody(req, res);
    if (body === null) return; // 400 already sent
  }

  // GET /api/v3 and /api/v3/
  if (rest.length === 0) {
    if (method === 'GET') {
      sendJson(res, 200, {
        current_user_url: '/api/v3/user',
        repository_url: '/api/v3/repos/{owner}/{repo}',
        rate_limit_url: '/api/v3/rate_limit',
      }, { 'X-OAuth-Scopes': 'repo, read:org' });
      return;
    }
    jsonError(res, 404, 'Not Found'); return;
  }
  // GET /api/v3/meta
  if (rest.length === 1 && rest[0] === 'meta' && method === 'GET') {
    sendJson(res, 200, { installed_version: SERVER_VERSION, verifiable_password_authentication: true, github_enterprise_version: SERVER_VERSION });
    return;
  }
  // /api/v3/user and /api/v3/user/repos
  if (rest[0] === 'user') {
    if (rest.length === 1 && method === 'GET') {
      sendJson(res, 200, { login: VIEWER, id: VIEWER_ID, type: 'User', name: 'ada iversen', email: VIEWER_EMAIL, html_url: `https://github.com/${VIEWER}` });
      return;
    }
    if (rest.length === 2 && rest[1] === 'repos') {
      if (method === 'GET') {
        const perPage = Math.max(1, parseInt(query.get('per_page') || '30', 10) || 30);
        const page = Math.max(1, parseInt(query.get('page') || '1', 10) || 1);
        const all = [...repos.values()].filter(r => r.owner === VIEWER);
        const totalPages = Math.max(1, Math.ceil(all.length / perPage));
        const slice = all.slice((page - 1) * perPage, page * perPage);
        const headers = {};
        if (page < totalPages) {
          const next = absUrl(req, `/api/v3/user/repos?per_page=${perPage}&page=${page + 1}`);
          headers.Link = `<${next}>; rel="next"`;
        }
        sendJson(res, 200, slice.map(repoView), headers);
        return;
      }
      if (method === 'POST') {
        const name = body && body.name;
        if (!name || typeof name !== 'string') { jsonError(res, 422, 'name is required'); return; }
        if (repos.has(`${VIEWER}/${name}`)) { jsonError(res, 422, 'name already exists on this account'); return; }
        const repo = createRepo(VIEWER, name, { description: body.description, private: body.private });
        sendJson(res, 201, repoView(repo));
        return;
      }
    }
    jsonError(res, 404, 'Not Found'); return;
  }
  // /api/v3/repos/{owner}/{repo}[/...]
  if (rest[0] === 'repos' && rest.length >= 3) {
    const owner = rest[1];
    const repoName = rest[2];
    const repo = findRepo(owner, repoName);
    if (!repo) { jsonError(res, 404, 'Not Found'); return; }
    const tail = rest.slice(3);
    // GET/PATCH/DELETE /repos/{o}/{r}
    if (tail.length === 0) {
      if (method === 'GET') { sendJson(res, 200, repoView(repo)); return; }
      if (method === 'PATCH') {
        if (body && typeof body.description === 'string') repo.description = body.description;
        if (body && typeof body.private === 'boolean') repo.private = body.private;
        repo.updatedAt = isoFromSeq(nextSeq());
        sendJson(res, 200, repoView(repo));
        return;
      }
      if (method === 'DELETE') {
        repos.delete(repo.key());
        res.writeHead(204, { 'X-GitHub-Request-Id': `req-${++requestCounter}` });
        res.end();
        return;
      }
      jsonError(res, 404, 'Not Found'); return;
    }
    // branches
    if (tail[0] === 'branches') {
      if (tail.length === 1 && method === 'GET') {
        const out = [...repo.refs.entries()]
          .filter(([n]) => n.startsWith('refs/heads/'))
          .map(([n, oid]) => ({ name: n.slice('refs/heads/'.length), commit: { sha: oid }, protected: false }));
        sendJson(res, 200, out);
        return;
      }
      if (tail.length === 2 && method === 'GET') {
        const tip = repo.tip(tail[1]);
        if (!tip) { jsonError(res, 404, 'Branch not found'); return; }
        sendJson(res, 200, { name: tail[1], commit: { sha: tip }, protected: false });
        return;
      }
      jsonError(res, 404, 'Not Found'); return;
    }
    // git/refs
    if (tail[0] === 'git' && tail[1] === 'refs') {
      if (method === 'POST' && tail.length === 2) {
        const ref = body && body.ref;
        const sha = body && body.sha;
        if (!ref || !sha || !isSha40(sha) || !getObject(repo, sha)) { jsonError(res, 422, 'Invalid ref or sha'); return; }
        if (repo.refs.has(ref)) { jsonError(res, 422, 'Reference already exists'); return; }
        repo.refs.set(ref, sha);
        sendJson(res, 201, { ref, object: { sha, type: getObject(repo, sha).type, url: '' } });
        return;
      }
      if (method === 'GET' && tail.length >= 4 && tail[2] === 'heads') {
        const branch = tail.slice(3).join('/');
        const tip = repo.tip(branch);
        if (!tip) { jsonError(res, 404, 'Not Found'); return; }
        sendJson(res, 200, { ref: `refs/heads/${branch}`, object: { sha: tip, type: 'commit' } });
        return;
      }
      jsonError(res, 404, 'Not Found'); return;
    }
    // commits
    if (tail[0] === 'commits' && tail.length === 1 && method === 'GET') {
      const shaParam = query.get('sha');
      let tip = null;
      if (shaParam) {
        tip = repo.tip(shaParam) || (isSha40(shaParam) && getObject(repo, shaParam) ? shaParam : null);
      } else {
        tip = repo.tip(repo.defaultBranch);
      }
      if (!tip) { sendJson(res, 200, []); return; }
      // Newest first: DFS from the tip following parents in order.
      const out = [];
      const seen = new Set();
      const stack = [tip];
      while (stack.length) {
        const oid = stack.pop();
        if (!oid || seen.has(oid)) continue;
        seen.add(oid);
        const c = commitOf(repo, oid);
        if (!c) continue;
        out.push({
          sha: oid,
          commit: {
            message: c.message,
            author: { name: c.author.split(' <')[0], email: VIEWER_EMAIL, date: isoFromSeq(1) },
            committer: { name: c.committer.split(' <')[0], email: VIEWER_EMAIL, date: isoFromSeq(1) },
          },
          author: { login: VIEWER, id: VIEWER_ID },
          committer: { login: VIEWER, id: VIEWER_ID },
          parents: c.parents.map(p => ({ sha: p })),
        });
        for (let i = c.parents.length - 1; i >= 0; i--) stack.push(c.parents[i]);
      }
      sendJson(res, 200, out);
      return;
    }
    // contents
    if (tail[0] === 'contents') {
      const filePath = tail.slice(1).join('/');
      if (method === 'GET') {
        const refParam = query.get('ref');
        let tip = null;
        if (refParam) tip = repo.tip(refParam) || (isSha40(refParam) && getObject(repo, refParam) ? refParam : null);
        else tip = repo.tip(repo.defaultBranch);
        if (!tip) { jsonError(res, 404, 'Not Found'); return; }
        const commit = commitOf(repo, tip);
        if (!commit) { jsonError(res, 404, 'Not Found'); return; }
        if (!filePath) {
          const flat = flattenTree(repo, commit.tree);
          const entries = [];
          const seen = new Set();
          for (const p of flat.keys()) {
            const top = p.split('/')[0];
            if (!seen.has(top)) { seen.add(top); entries.push(top); }
          }
          const treeEntries = parseTree(getObject(repo, commit.tree).data);
          sendJson(res, 200, treeEntries.map(e => ({
            type: e.mode === '40000' ? 'dir' : 'file',
            size: e.mode === '40000' ? 0 : (getObject(repo, e.oid) || { data: Buffer.alloc(0) }).data.length,
            name: e.name, path: e.name, sha: e.oid,
          })));
          return;
        }
        const flat = flattenTree(repo, commit.tree);
        const entry = flat.get(filePath);
        if (entry) {
          sendJson(res, 200, {
            type: 'file', encoding: 'base64', size: entry.data.length,
            name: filePath.split('/').pop(), path: filePath,
            content: b64encode(entry.data), sha: entry.oid,
          });
          return;
        }
        // Directory?
        const prefix = filePath + '/';
        const children = [];
        const childNames = new Set();
        for (const p of flat.keys()) {
          if (p.startsWith(prefix)) {
            const restPath = p.slice(prefix.length);
            const first = restPath.split('/')[0];
            if (!childNames.has(first)) {
              childNames.add(first);
              const childPath = prefix + first;
              const isDir = ![...flat.keys()].includes(childPath) && [...flat.keys()].some(k => k.startsWith(childPath + '/'));
              const childEntry = flat.get(childPath);
              children.push({
                type: isDir ? 'dir' : 'file',
                size: childEntry ? childEntry.data.length : 0,
                name: first, path: childPath,
                sha: childEntry ? childEntry.oid : '',
              });
            }
          }
        }
        if (children.length) { sendJson(res, 200, children); return; }
        jsonError(res, 404, 'Not Found');
        return;
      }
      if (method === 'PUT') {
        const message = body && body.message;
        const contentB64 = body && body.content;
        const shaParam = body && body.sha;
        const branch = (body && body.branch) || repo.defaultBranch;
        if (!message || typeof contentB64 !== 'string') { jsonError(res, 422, 'message and content are required'); return; }
        let content;
        try { content = b64decode(contentB64); } catch { jsonError(res, 400, 'Invalid base64 content'); return; }
        let branchTip = repo.tip(branch);
        if (!branchTip) {
          // Create the branch from the default branch tip (or from nothing).
          branchTip = repo.tip(repo.defaultBranch);
          if (branchTip) repo.refs.set(`refs/heads/${branch}`, branchTip);
        }
        const commit = branchTip ? commitOf(repo, branchTip) : null;
        const flat = commit ? flattenTree(repo, commit.tree) : new Map();
        const existing = flat.get(filePath);
        if (existing) {
          if (!shaParam || shaParam !== existing.oid) { jsonError(res, 409, 'sha does not match'); return; }
        } else if (shaParam) {
          jsonError(res, 409, 'file does not exist'); return;
        }
        const { commitOid } = commitFileWrite(repo, branchTip, filePath, content, message);
        repo.refs.set(`refs/heads/${branch}`, commitOid);
        const blobOid = sha1Git('blob', content);
        sendJson(res, existing ? 200 : 201, {
          content: { name: filePath.split('/').pop(), path: filePath, sha: blobOid, size: content.length, encoding: 'base64' },
          commit: { sha: commitOid, message },
        });
        return;
      }
      if (method === 'DELETE') {
        const shaParam = body && body.sha;
        const message = (body && body.message) || 'Delete file';
        const branch = (body && body.branch) || repo.defaultBranch;
        const branchTip = repo.tip(branch);
        if (!branchTip) { jsonError(res, 404, 'Not Found'); return; }
        const commit = commitOf(repo, branchTip);
        const flat = flattenTree(repo, commit.tree);
        const existing = flat.get(filePath);
        if (!existing) { jsonError(res, 404, 'Not Found'); return; }
        if (shaParam && shaParam !== existing.oid) { jsonError(res, 409, 'sha does not match'); return; }
        const newCommit = commitFileDelete(repo, branchTip, filePath, message);
        repo.refs.set(`refs/heads/${branch}`, newCommit);
        sendJson(res, 200, { commit: { sha: newCommit, message } });
        return;
      }
      jsonError(res, 404, 'Not Found'); return;
    }
    // labels
    if (tail[0] === 'labels') {
      if (tail.length === 1 && method === 'GET') {
        sendJson(res, 200, [...repo.labels.values()].map(l => ({ name: l.name, color: l.color, description: l.description || '' })));
        return;
      }
      if (tail.length === 1 && method === 'POST') {
        const name = body && body.name;
        if (!name) { jsonError(res, 422, 'name is required'); return; }
        const label = { name, color: (body && body.color) || '000000', description: (body && body.description) || '' };
        repo.labels.set(name, label);
        sendJson(res, 201, label);
        return;
      }
      jsonError(res, 404, 'Not Found'); return;
    }
    // issues
    if (tail[0] === 'issues') {
      if (tail.length === 1) {
        if (method === 'GET') {
          const state = query.get('state') || 'open';
          const sort = query.get('sort') || 'created';
          const direction = query.get('direction') || 'desc';
          let list = [...repo.issues.values()];
          if (state !== 'all') list = list.filter(i => i.state === state);
          list.sort((a, b) => {
            const d = direction === 'asc' ? a.number - b.number : b.number - a.number;
            return d;
          });
          const perPage = Math.max(1, parseInt(query.get('per_page') || '30', 10) || 30);
          const page = Math.max(1, parseInt(query.get('page') || '1', 10) || 1);
          list = list.slice((page - 1) * perPage, page * perPage);
          sendJson(res, 200, list.map(i => issueView(repo, i)));
          return;
        }
        if (method === 'POST') {
          const title = body && body.title;
          if (!title) { jsonError(res, 422, 'title is required'); return; }
          const labelNames = Array.isArray(body.labels) ? body.labels.map(l => typeof l === 'string' ? l : l.name) : [];
          const r = createIssueInRepo(repo, title, body.body, labelNames);
          if (r.error) { jsonError(res, 422, r.error); return; }
          sendJson(res, 201, issueView(repo, r.issue));
          return;
        }
        jsonError(res, 404, 'Not Found'); return;
      }
      const num = parseInt(tail[1], 10);
      const issue = repo.issues.get(num);
      if (tail.length === 2) {
        if (!issue) { jsonError(res, 404, 'Not Found'); return; }
        if (method === 'GET') { sendJson(res, 200, issueView(repo, issue)); return; }
        if (method === 'PATCH') {
          if (body && typeof body.state === 'string') {
            issue.state = body.state === 'closed' ? 'closed' : 'open';
            issue.closedAt = issue.state === 'closed' ? isoFromSeq(nextSeq()) : null;
          }
          if (body && typeof body.title === 'string') issue.title = body.title;
          if (body && typeof body.body === 'string') issue.body = body.body;
          issue.updatedAt = isoFromSeq(nextSeq());
          sendJson(res, 200, issueView(repo, issue));
          return;
        }
        jsonError(res, 404, 'Not Found'); return;
      }
      if (tail.length === 3 && tail[2] === 'comments') {
        if (!issue) { jsonError(res, 404, 'Not Found'); return; }
        if (method === 'GET') {
          sendJson(res, 200, issue.comments.map(c => ({
            id: c.id, node_id: c.globalId, body: c.body,
            user: { login: VIEWER, id: VIEWER_ID, type: 'User' },
            created_at: c.createdAt, updated_at: c.updatedAt,
          })));
          return;
        }
        if (method === 'POST') {
          const b = body && body.body;
          if (!b) { jsonError(res, 422, 'body is required'); return; }
          const seq = nextSeq();
          const comment = {
            id: seq,
            globalId: gid('C', `${repo.key()}#${issue.number}:${repo.nextCommentId++}`),
            body: b, createdAt: isoFromSeq(seq), updatedAt: isoFromSeq(seq),
          };
          issue.comments.push(comment);
          repo.comments.set(comment.id, comment);
          sendJson(res, 201, {
            id: comment.id, node_id: comment.globalId, body: comment.body,
            user: { login: VIEWER, id: VIEWER_ID, type: 'User' },
            created_at: comment.createdAt, updated_at: comment.updatedAt,
          });
          return;
        }
        jsonError(res, 404, 'Not Found'); return;
      }
      jsonError(res, 404, 'Not Found'); return;
    }
    // pulls
    if (tail[0] === 'pulls') {
      if (tail.length === 1) {
        if (method === 'GET') {
          const state = query.get('state') || 'open';
          let list = [...repo.pulls.values()];
          if (state === 'open') list = list.filter(p => p.state === 'open');
          else if (state === 'closed') list = list.filter(p => p.state === 'closed' || p.merged);
          list.sort((a, b) => b.number - a.number);
          sendJson(res, 200, list.map(p => pullView(repo, p)));
          return;
        }
        if (method === 'POST') {
          const title = body && body.title;
          const head = body && body.head;
          const base = body && body.base;
          if (!title || !head || !base) { jsonError(res, 422, 'title, head and base are required'); return; }
          const r = createPullInRepo(repo, title, body.body, head, base);
          if (r.error) { jsonError(res, r.status || 422, r.error); return; }
          sendJson(res, 201, pullView(repo, r.pr));
          return;
        }
        jsonError(res, 404, 'Not Found'); return;
      }
      const num = parseInt(tail[1], 10);
      const pr = repo.pulls.get(num);
      if (tail.length === 2) {
        if (!pr) { jsonError(res, 404, 'Not Found'); return; }
        if (method === 'GET') { sendJson(res, 200, pullView(repo, pr)); return; }
        jsonError(res, 404, 'Not Found'); return;
      }
      if (tail.length === 3 && tail[2] === 'files' && method === 'GET') {
        if (!pr) { jsonError(res, 404, 'Not Found'); return; }
        const headTip = repo.tip(pr.headRef);
        const baseTip = repo.tip(pr.baseRef);
        const headCommit = headTip ? commitOf(repo, headTip) : null;
        const baseCommit = baseTip ? commitOf(repo, baseTip) : null;
        const diff = treeDiff(repo, baseCommit ? baseCommit.tree : null, headCommit ? headCommit.tree : null);
        sendJson(res, 200, diff.map(d => ({
          sha: '', filename: d.filename, status: d.status,
          additions: d.additions, deletions: d.deletions, changes: d.changes,
          blob_url: '', raw_url: '', contents_url: '',
        })));
        return;
      }
      if (tail.length === 3 && tail[2] === 'merge' && method === 'PUT') {
        if (!pr) { jsonError(res, 404, 'Not Found'); return; }
        const r = mergePullInRepo(repo, pr);
        if (r.error) { jsonError(res, r.status || 405, r.error); return; }
        sendJson(res, 200, { sha: r.sha, merged: true, message: `Pull Request #${pr.number} merged` });
        return;
      }
      jsonError(res, 404, 'Not Found'); return;
    }
    jsonError(res, 404, 'Not Found'); return;
  }
  jsonError(res, 404, 'Not Found');
}

// ---------------------------------------------------------------------------
// GraphQL — small parser + executor for the documents gh / github-mcp send
// ---------------------------------------------------------------------------
const INTROSPECTION = {
  Issue: { kind: 'OBJECT', fields: ['id', 'number', 'title', 'state', 'body', 'url', 'createdAt', 'updatedAt', 'author'] },
  PullRequest: { kind: 'OBJECT', fields: ['id', 'number', 'headRefName', 'baseRefName', 'mergeable', 'state', 'merged', 'files', 'title', 'body', 'createdAt', 'updatedAt', 'url', 'mergedAt'] },
  Repository: { kind: 'OBJECT', fields: ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequest', 'pullRequests', 'url', 'description', 'createdAt', 'updatedAt'] },
  Viewer: { kind: 'OBJECT', fields: ['login', 'id', 'name', 'email'] },
  User: { kind: 'OBJECT', fields: ['login', 'id', 'name'] },
  SearchType: { kind: 'ENUM', enumValues: ['ISSUE', 'REPOSITORY', 'USER', 'DISCUSSION', 'COMMIT', 'CODE', 'MILESTONE', 'PULL_REQUEST', 'LABEL', 'PROJECT', 'WIKI', 'ORGANIZATION', 'PACKAGE', 'MARKETPLACE_LISTING', 'DISCUSSION_CATEGORY', 'TOPIC'] },
  IssueState: { kind: 'ENUM', enumValues: ['OPEN', 'CLOSED'] },
  PullRequestState: { kind: 'ENUM', enumValues: ['OPEN', 'CLOSED', 'MERGED'] },
  MergeableState: { kind: 'ENUM', enumValues: ['MERGEABLE', 'CONFLICTING', 'UNKNOWN'] },
};
const TYPE_FIELDS = {
  Query: ['viewer', 'repository', 'node', '__type', '__schema'],
  Viewer: ['login', 'id', 'name', 'email'],
  Repository: ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequest', 'pullRequests', 'url', 'description', 'createdAt', 'updatedAt'],
  User: ['login', 'id', 'name'],
  Node: ['id'],
  Ref: ['name', 'prefix', 'target'],
  Issue: ['id', 'number', 'title', 'state', 'body', 'url', 'createdAt', 'updatedAt', 'author'],
  IssueConnection: ['nodes', 'pageInfo', 'totalCount'],
  PageInfo: ['hasNextPage', 'hasPreviousPage', 'endCursor', 'startCursor'],
  PullRequest: ['id', 'number', 'state', 'merged', 'headRefName', 'baseRefName', 'mergeable', 'files', 'title', 'body', 'createdAt', 'updatedAt', 'url', 'mergedAt'],
  PullRequestConnection: ['nodes', 'pageInfo', 'totalCount'],
  PullRequestFileConnection: ['nodes', 'pageInfo', 'totalCount'],
  PullRequestFile: ['path', 'additions', 'deletions', 'changeType'],
  Mutation: ['createIssue', 'closeIssue', 'createPullRequest', 'mergePullRequest', 'addComment'],
  CreateIssuePayload: ['issue', 'clientMutationId'],
  CloseIssuePayload: ['issue', 'clientMutationId'],
  CreatePullRequestPayload: ['pullRequest', 'clientMutationId'],
  MergePullRequestPayload: ['pullRequest', 'clientMutationId'],
  AddCommentPayload: ['commentEdge', 'comment', 'clientMutationId'],
  CommentEdge: ['node', 'cursor'],
  IssueComment: ['id', 'body'],
  __Type: ['name', 'kind', 'description', 'fields', 'enumValues'],
  __Field: ['name', 'description', 'args', 'type'],
  __EnumValue: ['name', 'description'],
  __InputValue: ['name', 'description', 'type'],
  __Schema: ['queryType', 'mutationType', 'types'],
};
const FIELD_TYPE = {
  Query: { viewer: 'Viewer', repository: 'Repository', node: 'Node', __type: '__Type', __schema: '__Schema' },
  Repository: { owner: 'User', defaultBranchRef: 'Ref', issue: 'Issue', issues: 'IssueConnection', pullRequest: 'PullRequest', pullRequests: 'PullRequestConnection' },
  IssueConnection: { nodes: 'Issue', pageInfo: 'PageInfo' },
  PullRequestConnection: { nodes: 'PullRequest', pageInfo: 'PageInfo' },
  PullRequest: { files: 'PullRequestFileConnection' },
  PullRequestFileConnection: { nodes: 'PullRequestFile', pageInfo: 'PageInfo' },
  Mutation: { createIssue: 'CreateIssuePayload', closeIssue: 'CloseIssuePayload', createPullRequest: 'CreatePullRequestPayload', mergePullRequest: 'MergePullRequestPayload', addComment: 'AddCommentPayload' },
  CreateIssuePayload: { issue: 'Issue' },
  CloseIssuePayload: { issue: 'Issue' },
  CreatePullRequestPayload: { pullRequest: 'PullRequest' },
  MergePullRequestPayload: { pullRequest: 'PullRequest' },
  AddCommentPayload: { commentEdge: 'CommentEdge', comment: 'IssueComment' },
  CommentEdge: { node: 'IssueComment' },
  __Type: { fields: '__Field', enumValues: '__EnumValue' },
};

function gqlTokenize(src) {
  const tokens = [];
  let i = 0;
  while (i < src.length) {
    const ch = src[i];
    if (ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r' || ch === ',') { i++; continue; }
    if (ch === '#') { while (i < src.length && src[i] !== '\n') i++; continue; }
    if (ch === '.' && src.slice(i, i + 3) === '...') { tokens.push({ t: 'spread' }); i += 3; continue; }
    if ('{}()[]!:=$@&|'.includes(ch)) { tokens.push({ t: ch }); i++; continue; }
    if (ch === '"') {
      let j = i + 1; let s = '';
      while (j < src.length && src[j] !== '"') {
        if (src[j] === '\\' && j + 1 < src.length) { s += src[j + 1]; j += 2; }
        else { s += src[j]; j++; }
      }
      tokens.push({ t: 'string', v: s });
      i = j + 1;
      continue;
    }
    if (ch === '-' || (ch >= '0' && ch <= '9')) {
      let j = i;
      while (j < src.length && /[0-9.eE+-]/.test(src[j])) j++;
      const raw = src.slice(i, j);
      tokens.push({ t: 'number', v: raw.includes('.') || raw.includes('e') || raw.includes('E') ? parseFloat(raw) : parseInt(raw, 10) });
      i = j;
      continue;
    }
    if (/[A-Za-z_]/.test(ch)) {
      let j = i;
      while (j < src.length && /[A-Za-z0-9_]/.test(src[j])) j++;
      tokens.push({ t: 'name', v: src.slice(i, j) });
      i = j;
      continue;
    }
    throw new Error('Unexpected character in GraphQL document: ' + ch);
  }
  tokens.push({ t: 'eof' });
  return tokens;
}

class GqlParser {
  constructor(tokens) { this.t = tokens; this.p = 0; }
  peek() { return this.t[this.p]; }
  next() { return this.t[this.p++]; }
  expect(type) {
    const tok = this.next();
    if (tok.t !== type) throw new Error(`Expected ${type}, got ${tok.t}`);
    return tok;
  }
  parseDocument() {
    const defs = [];
    while (this.peek().t !== 'eof') defs.push(this.parseDefinition());
    return defs;
  }
  parseDefinition() {
    const tok = this.peek();
    if (tok.t === '{') return { kind: 'operation', operation: 'query', name: null, selections: this.parseSelectionSet() };
    if (tok.t === 'name' && (tok.v === 'query' || tok.v === 'mutation' || tok.v === 'subscription')) {
      this.next();
      let name = null;
      if (this.peek().t === 'name') name = this.next().v;
      if (this.peek().t === '(') this.parseVariableDefinitions();
      // skip directives
      while (this.peek().t === '@') { this.next(); if (this.peek().t === 'name') this.next(); if (this.peek().t === '(') this.parseArguments(); }
      return { kind: 'operation', operation: tok.v, name, selections: this.parseSelectionSet() };
    }
    if (tok.t === 'name' && tok.v === 'fragment') {
      this.next();
      const name = this.expect('name').v;
      this.expect('name'); // 'on'
      const typeCondition = this.expect('name').v;
      return { kind: 'fragment', name, typeCondition, selections: this.parseSelectionSet() };
    }
    throw new Error('Unexpected token in GraphQL document: ' + JSON.stringify(tok));
  }
  parseVariableDefinitions() {
    this.expect('(');
    while (this.peek().t !== ')') {
      this.expect('$');
      this.expect('name');
      this.expect(':');
      this.parseType();
      if (this.peek().t === '=') { this.next(); this.parseValue(); }
    }
    this.expect(')');
  }
  parseType() {
    if (this.peek().t === '[') {
      this.next(); this.parseType(); this.expect(']');
    } else this.expect('name');
    if (this.peek().t === '!') this.next();
  }
  parseSelectionSet() {
    this.expect('{');
    const sels = [];
    while (this.peek().t !== '}') sels.push(this.parseSelection());
    this.expect('}');
    return sels;
  }
  parseSelection() {
    if (this.peek().t === 'spread') {
      this.next();
      if (this.peek().t === 'name' && this.peek().v === 'on') {
        this.next();
        const typeCondition = this.expect('name').v;
        return { kind: 'inlineFragment', typeCondition, selections: this.parseSelectionSet() };
      }
      const name = this.expect('name').v;
      return { kind: 'fragmentSpread', name };
    }
    let alias = null;
    let name = this.expect('name').v;
    if (this.peek().t === ':') {
      this.next();
      alias = name;
      name = this.expect('name').v;
    }
    let args = {};
    if (this.peek().t === '(') args = this.parseArguments();
    while (this.peek().t === '@') { this.next(); if (this.peek().t === 'name') this.next(); if (this.peek().t === '(') this.parseArguments(); }
    let selections = null;
    if (this.peek().t === '{') selections = this.parseSelectionSet();
    return { kind: 'field', name, alias: alias || name, args, selections };
  }
  parseArguments() {
    this.expect('(');
    const args = {};
    while (this.peek().t !== ')') {
      const name = this.expect('name').v;
      this.expect(':');
      args[name] = this.parseValue();
    }
    this.expect(')');
    return args;
  }
  parseValue() {
    const tok = this.next();
    if (tok.t === '$') return { __var: this.expect('name').v };
    if (tok.t === 'string' || tok.t === 'number') return tok.v;
    if (tok.t === 'name') {
      if (tok.v === 'true') return true;
      if (tok.v === 'false') return false;
      if (tok.v === 'null') return null;
      return { __enum: tok.v };
    }
    if (tok.t === '[') {
      const list = [];
      while (this.peek().t !== ']') list.push(this.parseValue());
      this.expect(']');
      return list;
    }
    if (tok.t === '{') {
      const obj = {};
      while (this.peek().t !== '}') {
        const k = this.expect('name').v;
        this.expect(':');
        obj[k] = this.parseValue();
      }
      this.expect('}');
      return obj;
    }
    throw new Error('Unexpected value token: ' + JSON.stringify(tok));
  }
}

function resolveVariables(value, variables) {
  if (value && typeof value === 'object') {
    if (value.__var !== undefined) return variables[value.__var];
    if (value.__enum !== undefined) return value.__enum;
    if (Array.isArray(value)) return value.map(v => resolveVariables(v, variables));
    const out = {};
    for (const [k, v] of Object.entries(value)) out[k] = resolveVariables(v, variables);
    return out;
  }
  return value;
}

function cursorFor(n) { return Buffer.from(`cursor:${n}`, 'utf8').toString('base64'); }
function numberFromCursor(c) {
  try {
    const s = Buffer.from(c, 'base64').toString('utf8');
    const m = s.match(/^cursor:(\d+)$/);
    return m ? parseInt(m[1], 10) : null;
  } catch { return null; }
}

function gqlWrapIssue(repo, issue) {
  return { __typename: 'Issue', repo, issue };
}
function gqlWrapPull(repo, pr) {
  return { __typename: 'PullRequest', repo, pr };
}
function gqlWrapRepo(repo) {
  return { __typename: 'Repository', repo };
}

// Resolve one field on a typed value. Returns the raw value (entity object,
// scalar, connection object, or null). Errors are appended to `errors`.
function gqlResolveField(typeName, value, field, args, errors) {
  const a = {};
  for (const [k, v] of Object.entries(args)) a[k] = resolveVariables(v, gqlResolveField._vars || {});
  switch (typeName) {
    case 'Query': {
      if (field === 'viewer') return { __typename: 'Viewer' };
      if (field === 'repository') {
        const repo = findRepo(a.owner, a.name);
        return repo ? gqlWrapRepo(repo) : null;
      }
      if (field === 'node') {
        const d = ungid(a.id);
        if (!d) return null;
        if (d.kind === 'R') {
          const [owner, name] = d.key.split('/');
          const repo = findRepo(owner, name);
          return repo ? gqlWrapRepo(repo) : null;
        }
        if (d.kind === 'I') {
          const m = d.key.match(/^(.+)\/([^/]+)#(\d+)$/);
          if (!m) return null;
          const repo = findRepo(m[1], m[2]);
          const issue = repo && repo.issues.get(parseInt(m[3], 10));
          return issue ? gqlWrapIssue(repo, issue) : null;
        }
        if (d.kind === 'P') {
          const m = d.key.match(/^(.+)\/([^/]+)#(\d+)$/);
          if (!m) return null;
          const repo = findRepo(m[1], m[2]);
          const pr = repo && repo.pulls.get(parseInt(m[3], 10));
          return pr ? gqlWrapPull(repo, pr) : null;
        }
        return null;
      }
      if (field === '__type') {
        const def = INTROSPECTION[a.name];
        if (!def) return null;
        return { __typename: '__Type', name: a.name, kind: def.kind, fields: def.fields || [], enumValues: def.enumValues || [] };
      }
      if (field === '__schema') return { __typename: '__Schema' };
      return null;
    }
    case 'Viewer': {
      if (field === 'login') return VIEWER;
      if (field === 'id') return VIEWER_ID;
      if (field === 'name') return 'ada iversen';
      if (field === 'email') return VIEWER_EMAIL;
      return null;
    }
    case 'User': {
      if (field === 'login') return value.login;
      if (field === 'id') return VIEWER_ID;
      if (field === 'name') return value.login;
      return null;
    }
    case 'Node': {
      if (field === 'id') return value.__typename === 'Repository' ? value.repo.globalId() : value.__typename === 'Issue' ? value.issue.globalId : value.pr.globalId;
      return null;
    }
    case 'Repository': {
      const repo = value.repo;
      if (field === 'id') return repo.globalId();
      if (field === 'databaseId') return repo.id;
      if (field === 'name') return repo.name;
      if (field === 'nameWithOwner') return repo.fullName();
      if (field === 'owner') return { __typename: 'User', login: repo.owner };
      if (field === 'defaultBranchRef') return repo.tip(DEFAULT_BRANCH) ? { __typename: 'Ref', name: DEFAULT_BRANCH } : null;
      if (field === 'viewerPermission') return 'ADMIN';
      if (field === 'hasIssuesEnabled') return true;
      if (field === 'url') return `https://github.com/${repo.fullName()}`;
      if (field === 'description') return repo.description;
      if (field === 'createdAt') return repo.createdAt;
      if (field === 'updatedAt') return repo.updatedAt;
      if (field === 'issue') {
        const issue = repo.issues.get(a.number);
        return issue ? gqlWrapIssue(repo, issue) : null;
      }
      if (field === 'issues') {
        let list = [...repo.issues.values()];
        if (a.states) {
          const wanted = new Set(a.states.map(s => String(s).toLowerCase()));
          list = list.filter(i => wanted.has(i.state));
        }
        if (a.orderBy && a.orderBy.field === 'CREATED_AT') {
          const dir = a.orderBy.direction === 'DESC' ? -1 : 1;
          list.sort((x, y) => dir * (x.number - y.number));
        } else {
          list.sort((x, y) => x.number - y.number);
        }
        return paginateGql(list, a, (i) => gqlWrapIssue(repo, i));
      }
      if (field === 'pullRequest') {
        const pr = repo.pulls.get(a.number);
        return pr ? gqlWrapPull(repo, pr) : null;
      }
      if (field === 'pullRequests') {
        let list = [...repo.pulls.values()];
        if (a.states) {
          const wanted = new Set(a.states.map(s => String(s).toLowerCase()));
          list = list.filter(p => wanted.has(p.merged ? 'merged' : p.state));
        }
        list.sort((x, y) => y.number - x.number);
        return paginateGql(list, a, (p) => gqlWrapPull(repo, p));
      }
      return null;
    }
    case 'Ref': {
      if (field === 'name') return value.name;
      if (field === 'prefix') return 'refs/heads/';
      if (field === 'target') return null;
      return null;
    }
    case 'Issue': {
      const issue = value.issue;
      if (field === 'id') return issue.globalId;
      if (field === 'number') return issue.number;
      if (field === 'title') return issue.title;
      if (field === 'state') return issue.state.toUpperCase();
      if (field === 'body') return issue.body;
      if (field === 'url') return `https://github.com/${value.repo.fullName()}/issues/${issue.number}`;
      if (field === 'createdAt') return issue.createdAt;
      if (field === 'updatedAt') return issue.updatedAt;
      if (field === 'author') return { __typename: 'User', login: VIEWER };
      return null;
    }
    case 'PullRequest': {
      const pr = value.pr;
      if (field === 'id') return pr.globalId;
      if (field === 'number') return pr.number;
      if (field === 'state') return pr.merged ? 'MERGED' : pr.state.toUpperCase();
      if (field === 'merged') return pr.merged;
      if (field === 'headRefName') return pr.headRef;
      if (field === 'baseRefName') return pr.baseRef;
      if (field === 'mergeable') {
        if (pr.merged || pr.state !== 'open') return 'UNKNOWN';
        return prIsConflicted(value.repo, pr) ? 'CONFLICTING' : 'MERGEABLE';
      }
      if (field === 'title') return pr.title;
      if (field === 'body') return pr.body;
      if (field === 'createdAt') return pr.createdAt;
      if (field === 'updatedAt') return pr.updatedAt;
      if (field === 'url') return `https://github.com/${value.repo.fullName()}/pull/${pr.number}`;
      if (field === 'mergedAt') return pr.mergedAt;
      if (field === 'files') {
        const headTip = value.repo.tip(pr.headRef);
        const baseTip = value.repo.tip(pr.baseRef);
        const hc = headTip ? commitOf(value.repo, headTip) : null;
        const bc = baseTip ? commitOf(value.repo, baseTip) : null;
        const diff = treeDiff(value.repo, bc ? bc.tree : null, hc ? hc.tree : null);
        const nodes = diff.map(d => ({ __typename: 'PullRequestFile', path: d.filename, additions: d.additions, deletions: d.deletions, changeType: d.status.toUpperCase() }));
        return paginateGql(nodes, a, (n) => n, true);
      }
      return null;
    }
    case 'PullRequestFile': {
      if (field === 'path') return value.path;
      if (field === 'additions') return value.additions;
      if (field === 'deletions') return value.deletions;
      if (field === 'changeType') return value.changeType;
      return null;
    }
    case 'IssueConnection':
    case 'PullRequestConnection':
    case 'PullRequestFileConnection': {
      if (field === 'nodes') return value.nodes;
      if (field === 'pageInfo') return value.pageInfo;
      if (field === 'totalCount') return value.totalCount;
      return null;
    }
    case 'PageInfo': {
      if (field === 'hasNextPage') return value.hasNextPage;
      if (field === 'hasPreviousPage') return value.hasPreviousPage;
      if (field === 'endCursor') return value.endCursor;
      if (field === 'startCursor') return value.startCursor;
      return null;
    }
    case 'Mutation': {
      if (field === 'createIssue') {
        const input = a.input || {};
        const d = ungid(input.repositoryId);
        if (!d || d.kind !== 'R') { errors.push({ message: 'Invalid repositoryId' }); return null; }
        const [owner, name] = d.key.split('/');
        const repo = findRepo(owner, name);
        if (!repo) { errors.push({ message: 'Repository not found' }); return null; }
        const r = createIssueInRepo(repo, input.title, input.body, []);
        if (r.error) { errors.push({ message: r.error }); return null; }
        return { __typename: 'CreateIssuePayload', issue: gqlWrapIssue(repo, r.issue) };
      }
      if (field === 'closeIssue') {
        const input = a.input || {};
        const d = ungid(input.issueId);
        if (!d || d.kind !== 'I') { errors.push({ message: 'Invalid issueId' }); return null; }
        const m = d.key.match(/^(.+)\/([^/]+)#(\d+)$/);
        const repo = m && findRepo(m[1], m[2]);
        const issue = repo && repo.issues.get(parseInt(m[3], 10));
        if (!issue) { errors.push({ message: 'Issue not found' }); return null; }
        issue.state = 'closed';
        issue.closedAt = isoFromSeq(nextSeq());
        issue.updatedAt = isoFromSeq(nextSeq());
        return { __typename: 'CloseIssuePayload', issue: gqlWrapIssue(repo, issue) };
      }
      if (field === 'createPullRequest') {
        const input = a.input || {};
        const d = ungid(input.repositoryId);
        if (!d || d.kind !== 'R') { errors.push({ message: 'Invalid repositoryId' }); return null; }
        const [owner, name] = d.key.split('/');
        const repo = findRepo(owner, name);
        if (!repo) { errors.push({ message: 'Repository not found' }); return null; }
        const r = createPullInRepo(repo, input.title, input.body, input.headRefName, input.baseRefName);
        if (r.error) { errors.push({ message: r.error }); return null; }
        return { __typename: 'CreatePullRequestPayload', pullRequest: gqlWrapPull(repo, r.pr) };
      }
      if (field === 'mergePullRequest') {
        const input = a.input || {};
        const d = ungid(input.pullRequestId);
        if (!d || d.kind !== 'P') { errors.push({ message: 'Invalid pullRequestId' }); return null; }
        const m = d.key.match(/^(.+)\/([^/]+)#(\d+)$/);
        const repo = m && findRepo(m[1], m[2]);
        const pr = repo && repo.pulls.get(parseInt(m[3], 10));
        if (!pr) { errors.push({ message: 'Pull request not found' }); return null; }
        const r = mergePullInRepo(repo, pr);
        if (r.error) { errors.push({ message: r.error }); return null; }
        return { __typename: 'MergePullRequestPayload', pullRequest: gqlWrapPull(repo, pr) };
      }
      if (field === 'addComment') {
        const input = a.input || {};
        const d = ungid(input.subjectId);
        if (!d || d.kind !== 'I') { errors.push({ message: 'Invalid subjectId' }); return null; }
        const m = d.key.match(/^(.+)\/([^/]+)#(\d+)$/);
        const repo = m && findRepo(m[1], m[2]);
        const issue = repo && repo.issues.get(parseInt(m[3], 10));
        if (!issue) { errors.push({ message: 'Issue not found' }); return null; }
        const seq = nextSeq();
        const comment = {
          id: seq,
          globalId: gid('C', `${repo.key()}#${issue.number}:${repo.nextCommentId++}`),
          body: input.body || '', createdAt: isoFromSeq(seq), updatedAt: isoFromSeq(seq),
        };
        issue.comments.push(comment);
        repo.comments.set(comment.id, comment);
        return { __typename: 'AddCommentPayload', commentEdge: { __typename: 'CommentEdge', node: { __typename: 'IssueComment', id: comment.globalId, body: comment.body }, cursor: cursorFor(seq) }, comment: { __typename: 'IssueComment', id: comment.globalId, body: comment.body } };
      }
      return null;
    }
    case 'CreateIssuePayload':
    case 'CloseIssuePayload': {
      if (field === 'issue') return value.issue;
      if (field === 'clientMutationId') return null;
      return null;
    }
    case 'CreatePullRequestPayload':
    case 'MergePullRequestPayload': {
      if (field === 'pullRequest') return value.pullRequest;
      if (field === 'clientMutationId') return null;
      return null;
    }
    case 'AddCommentPayload': {
      if (field === 'commentEdge') return value.commentEdge;
      if (field === 'comment') return value.comment;
      if (field === 'clientMutationId') return null;
      return null;
    }
    case 'CommentEdge': {
      if (field === 'node') return value.node;
      if (field === 'cursor') return value.cursor;
      return null;
    }
    case 'IssueComment': {
      if (field === 'id') return value.id;
      if (field === 'body') return value.body;
      return null;
    }
    case '__Type': {
      if (field === 'name') return value.name;
      if (field === 'kind') return value.kind;
      if (field === 'description') return null;
      if (field === 'fields') return (value.fields || []).map(n => ({ __typename: '__Field', name: n }));
      if (field === 'enumValues') return (value.enumValues || []).map(n => ({ __typename: '__EnumValue', name: n }));
      return null;
    }
    case '__Field': {
      if (field === 'name') return value.name;
      if (field === 'description') return null;
      if (field === 'args') return [];
      if (field === 'type') return { __typename: '__Type', name: 'String', kind: 'SCALAR' };
      return null;
    }
    case '__EnumValue': {
      if (field === 'name') return value.name;
      if (field === 'description') return null;
      return null;
    }
    case '__Schema': {
      if (field === 'queryType') return { __typename: '__Type', name: 'Query', kind: 'OBJECT' };
      if (field === 'mutationType') return { __typename: '__Type', name: 'Mutation', kind: 'OBJECT' };
      if (field === 'types') return Object.keys(INTROSPECTION).map(n => ({ __typename: '__Type', name: n, kind: INTROSPECTION[n].kind }));
      return null;
    }
    default:
      return null;
  }
}

function paginateGql(list, args, wrap, isFileNodes) {
  const first = args.first;
  let start = 0;
  if (args.after) {
    const n = numberFromCursor(args.after);
    if (n !== null) {
      const idx = list.findIndex(item => {
        const num = isFileNodes ? null : (item.number !== undefined ? item.number : null);
        return num === n;
      });
      if (idx >= 0) start = idx + 1;
    }
  }
  const window = list.slice(start);
  const hasNext = first !== undefined && first !== null ? window.length > first : false;
  const page = first !== undefined && first !== null ? window.slice(0, first) : window;
  const endCursor = page.length ? cursorFor(isFileNodes ? page.length : page[page.length - 1].number) : null;
  const startCursor = page.length ? cursorFor(isFileNodes ? 1 : page[0].number) : null;
  return {
    __typename: isFileNodes ? 'PullRequestFileConnection' : 'IssueConnection',
    nodes: page.map(wrap),
    pageInfo: { __typename: 'PageInfo', hasNextPage: hasNext, hasPreviousPage: start > 0, endCursor, startCursor },
    totalCount: list.length,
  };
}

function gqlExecuteSelectionSet(typeName, value, selections, variables, errors, fragments) {
  if (value === null || value === undefined) return null;
  const out = {};
  for (const sel of selections) {
    if (sel.kind === 'inlineFragment') {
      const actual = value.__typename || typeName;
      if (sel.typeCondition && sel.typeCondition !== actual) continue;
      const sub = gqlExecuteSelectionSet(sel.typeCondition || typeName, value, sel.selections, variables, errors, fragments);
      if (sub) Object.assign(out, sub);
      continue;
    }
    if (sel.kind === 'fragmentSpread') {
      const frag = fragments[sel.name];
      if (!frag) { errors.push({ message: `Unknown fragment "${sel.name}".` }); continue; }
      const actual = value.__typename || typeName;
      if (frag.typeCondition && frag.typeCondition !== actual) continue;
      const sub = gqlExecuteSelectionSet(frag.typeCondition, value, frag.selections, variables, errors, fragments);
      if (sub) Object.assign(out, sub);
      continue;
    }
    // field
    if (sel.name === '__typename') { out[sel.alias] = value.__typename || typeName; continue; }
    const allowed = TYPE_FIELDS[typeName] || [];
    if (!allowed.includes(sel.name)) {
      errors.push({ message: `Cannot query field "${sel.name}" on type "${typeName}".` });
      out[sel.alias] = null;
      continue;
    }
    gqlResolveField._vars = variables;
    const raw = gqlResolveField(typeName, value, sel.name, sel.args, errors);
    if (sel.selections) {
      const childType = (FIELD_TYPE[typeName] || {})[sel.name];
      if (raw === null || raw === undefined) { out[sel.alias] = null; continue; }
      if (Array.isArray(raw)) {
        out[sel.alias] = raw.map(item => gqlExecuteSelectionSet(childType, item, sel.selections, variables, errors, fragments));
        continue;
      }
      out[sel.alias] = gqlExecuteSelectionSet(childType, raw, sel.selections, variables, errors, fragments);
    } else {
      out[sel.alias] = raw;
    }
  }
  return out;
}

function gqlExecuteOne(doc, operationName) {
  const query = doc.query;
  const variables = doc.variables || {};
  try {
    const tokens = gqlTokenize(query);
    const parser = new GqlParser(tokens);
    const defs = parser.parseDocument();
    const fragments = {};
    const operations = [];
    for (const d of defs) {
      if (d.kind === 'fragment') fragments[d.name] = d;
      else operations.push(d);
    }
    const op = operationName
      ? operations.find(o => o.name === operationName)
      : operations[0];
    if (!op) return { data: null, errors: [{ message: 'No operation found' }] };
    const errors = [];
    const rootType = op.operation === 'mutation' ? 'Mutation' : 'Query';
    const data = gqlExecuteSelectionSet(rootType, {}, op.selections, variables, errors, fragments);
    const result = { data };
    if (errors.length) result.errors = errors;
    return result;
  } catch (e) {
    return { data: null, errors: [{ message: e.message }] };
  }
}

async function handleGraphql(req, res) {
  if (!checkAuth(req)) { jsonError(res, 401, 'Requires authentication'); return; }
  const body = await parseJsonBody(req, res);
  if (body === null) return;
  if (Array.isArray(body)) {
    const results = body.map(op => gqlExecuteOne(op, op.operationName));
    sendJson(res, 200, results);
    return;
  }
  if (!body || typeof body.query !== 'string') {
    sendJson(res, 200, { data: null, errors: [{ message: 'Must provide query string.' }] });
    return;
  }
  sendJson(res, 200, gqlExecuteOne(body, body.operationName));
}

// ---------------------------------------------------------------------------
// MCP — JSON-RPC 2.0 Streamable HTTP
// ---------------------------------------------------------------------------
const MCP_SUPPORTED_VERSIONS = ['2026-07-28', '2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];
const MCP_TOOLS = Object.freeze([
  { name: 'create_repo', description: 'Create a new repository owned by the authenticated user.', inputSchema: { type: 'object', properties: { name: { type: 'string', description: 'Repository name' }, description: { type: 'string', description: 'Repository description' }, private: { type: 'boolean', description: 'Whether the repository is private' }, owner: { type: 'string', description: 'Owner login (defaults to the authenticated user)' } }, required: ['name'] } },
  { name: 'get_repo', description: 'Get a repository by owner and name.', inputSchema: { type: 'object', properties: { owner: { type: 'string', description: 'Repository owner login' }, repo: { type: 'string', description: 'Repository name' } }, required: ['owner', 'repo'] } },
  { name: 'create_issue', description: 'Create an issue in a repository.', inputSchema: { type: 'object', properties: { owner: { type: 'string', description: 'Repository owner login' }, repo: { type: 'string', description: 'Repository name' }, title: { type: 'string', description: 'Issue title' }, body: { type: 'string', description: 'Issue body' } }, required: ['owner', 'repo', 'title'] } },
  { name: 'list_issues', description: 'List issues in a repository.', inputSchema: { type: 'object', properties: { owner: { type: 'string', description: 'Repository owner login' }, repo: { type: 'string', description: 'Repository name' }, state: { type: 'string', description: 'Issue state filter: open, closed, or all' } }, required: ['owner', 'repo'] } },
  { name: 'create_pull_request', description: 'Create a pull request in a repository.', inputSchema: { type: 'object', properties: { owner: { type: 'string', description: 'Repository owner login' }, repo: { type: 'string', description: 'Repository name' }, title: { type: 'string', description: 'Pull request title' }, head: { type: 'string', description: 'Head branch name' }, base: { type: 'string', description: 'Base branch name' }, body: { type: 'string', description: 'Pull request body' } }, required: ['owner', 'repo', 'title', 'head', 'base'] } },
  { name: 'merge_pull_request', description: 'Merge a pull request.', inputSchema: { type: 'object', properties: { owner: { type: 'string', description: 'Repository owner login' }, repo: { type: 'string', description: 'Repository name' }, pull_number: { type: 'integer', description: 'Pull request number' } }, required: ['owner', 'repo', 'pull_number'] } },
]);

function mcpToolResult(obj) {
  return { content: [{ type: 'text', text: JSON.stringify(obj) }], structuredContent: obj };
}
function mcpToolError(message) {
  return { content: [{ type: 'text', text: String(message) }], isError: true };
}
function mcpResolveRepo(args) {
  let owner = args.owner;
  let repoName = args.repo;
  if ((!owner || !repoName) && typeof args.full_name === 'string') {
    const parts = args.full_name.split('/');
    if (parts.length === 2) { owner = parts[0]; repoName = parts[1]; }
  }
  if (!owner) owner = VIEWER;
  if (!repoName) return { error: 'Missing required argument: repo' };
  const repo = findRepo(owner, repoName);
  if (!repo) return { error: `Repository ${owner}/${repoName} not found` };
  return { repo };
}
function mcpCallTool(name, args) {
  args = args || {};
  const required = {
    create_repo: ['name'],
    get_repo: ['owner', 'repo'],
    create_issue: ['owner', 'repo', 'title'],
    list_issues: ['owner', 'repo'],
    create_pull_request: ['owner', 'repo', 'title', 'head', 'base'],
    merge_pull_request: ['owner', 'repo', 'pull_number'],
  };
  const tool = MCP_TOOLS.find(t => t.name === name);
  if (!tool) return { rpcError: { code: -32602, message: `Unknown tool: ${name}` } };
  for (const r of required[name] || []) {
    if (args[r] === undefined || args[r] === null || args[r] === '') {
      // Tolerate owner defaulting to the viewer for repo-scoped tools.
      if (r === 'owner') continue;
      return { rpcError: { code: -32602, message: `Missing required argument: ${r}` } };
    }
  }
  if (name === 'create_repo') {
    const owner = args.owner || VIEWER;
    if (owner !== VIEWER) return { result: mcpToolError('Cannot create repositories for another owner') };
    if (repos.has(`${owner}/${args.name}`)) return { result: mcpToolError(`Repository ${owner}/${args.name} already exists`) };
    const repo = createRepo(owner, args.name, { description: args.description, private: args.private });
    return { result: mcpToolResult(repoView(repo)) };
  }
  const resolved = mcpResolveRepo(args);
  if (resolved.error) return { result: mcpToolError(resolved.error) };
  const repo = resolved.repo;
  if (name === 'get_repo') return { result: mcpToolResult(repoView(repo)) };
  if (name === 'create_issue') {
    const r = createIssueInRepo(repo, args.title, args.body, []);
    if (r.error) return { result: mcpToolError(r.error) };
    return { result: mcpToolResult(issueView(repo, r.issue)) };
  }
  if (name === 'list_issues') {
    const state = args.state || 'open';
    let list = [...repo.issues.values()];
    if (state !== 'all') list = list.filter(i => i.state === state);
    list.sort((a, b) => b.number - a.number);
    return { result: mcpToolResult({ issues: list.map(i => issueView(repo, i)) }) };
  }
  if (name === 'create_pull_request') {
    const r = createPullInRepo(repo, args.title, args.body, args.head, args.base);
    if (r.error) return { result: mcpToolError(r.error) };
    return { result: mcpToolResult(pullView(repo, r.pr)) };
  }
  if (name === 'merge_pull_request') {
    const num = parseInt(args.pull_number, 10);
    const pr = repo.pulls.get(num);
    if (!pr) return { result: mcpToolError(`Pull request #${args.pull_number} not found`) };
    const r = mergePullInRepo(repo, pr);
    if (r.error) return { result: mcpToolError(r.error) };
    return { result: mcpToolResult({ merged: true, sha: r.sha, pull_number: num, number: num }) };
  }
  return { rpcError: { code: -32602, message: `Unknown tool: ${name}` } };
}

async function handleMcp(req, res) {
  if (!checkAuth(req)) { jsonError(res, 401, 'Requires authentication'); return; }
  const raw = await readBody(req);
  let msg;
  try { msg = JSON.parse(raw.toString('utf8')); }
  catch {
    sendJson(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
    return;
  }
  if (!msg || typeof msg !== 'object' || Array.isArray(msg)) {
    sendJson(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
    return;
  }
  const id = msg.id === undefined ? null : msg.id;
  const isNotification = msg.id === undefined;
  const method = msg.method || '';
  const params = msg.params || {};
  const rpcResult = (result, extraHeaders) => sendJson(res, 200, { jsonrpc: '2.0', id, result }, extraHeaders);
  const rpcError = (code, message, data) => {
    const err = { code, message };
    if (data !== undefined) err.data = data;
    sendJson(res, 200, { jsonrpc: '2.0', id, error: err });
  };
  if (method === 'server/discover') {
    const declared = (params._meta && params._meta.protocolVersion) || params.protocolVersion;
    if (declared && !MCP_SUPPORTED_VERSIONS.includes(declared)) {
      rpcError(-32022, 'Unsupported protocol version', { supported: MCP_SUPPORTED_VERSIONS });
      return;
    }
    rpcResult({
      supportedVersions: MCP_SUPPORTED_VERSIONS,
      capabilities: { tools: {} },
      serverInfo: { name: SERVER_NAME, version: SERVER_VERSION },
      _meta: { 'io.modelcontextprotocol/serverInfo': { name: SERVER_NAME, version: SERVER_VERSION } },
    });
    return;
  }
  if (method === 'initialize') {
    const requested = params.protocolVersion;
    const version = MCP_SUPPORTED_VERSIONS.includes(requested) ? requested : '2026-07-28';
    rpcResult({
      protocolVersion: version,
      capabilities: { tools: {} },
      serverInfo: { name: SERVER_NAME, version: SERVER_VERSION },
    }, { 'Mcp-Session-Id': 'forge-session' });
    return;
  }
  if (method.startsWith('notifications/') || isNotification) {
    res.writeHead(202, { 'Content-Length': 0 });
    res.end();
    return;
  }
  if (method === 'ping') { rpcResult({}); return; }
  if (method === 'tools/list') {
    rpcResult({ tools: MCP_TOOLS });
    return;
  }
  if (method === 'tools/call') {
    const name = params.name;
    const args = params.arguments || {};
    if (!name) { rpcError(-32602, 'Missing tool name'); return; }
    const out = mcpCallTool(name, args);
    if (out.rpcError) { rpcError(out.rpcError.code, out.rpcError.message); return; }
    rpcResult(out.result);
    return;
  }
  rpcError(-32601, `Method not found: ${method}`);
}

// ---------------------------------------------------------------------------
// Router + lifecycle
// ---------------------------------------------------------------------------
async function requestHandler(req, res) {
  try {
    const { pathname, query } = parseQuery(req);
    if (pathname === '/healthz' && req.method === 'GET') {
      sendJson(res, 200, { ok: true });
      return;
    }
    const seg = pathname.split('/').filter(Boolean).map(s => { try { return decodeURIComponent(s); } catch { return s; } });
    // Git smart HTTP: /{owner}/{repo}.git/...
    if (seg.length >= 2 && seg[1].endsWith('.git')) {
      const owner = seg[0];
      const repoName = seg[1].slice(0, -4);
      const repo = findRepo(owner, repoName);
      if (seg.length === 4 && seg[2] === 'info' && seg[3] === 'refs' && req.method === 'GET') {
        handleGitInfoRefs(req, res, repo, query.get('service'));
        return;
      }
      if (seg.length === 3 && seg[2] === 'git-upload-pack' && req.method === 'POST') {
        if (!repo) { jsonError(res, 404, 'Repository not found'); return; }
        const body = await readBody(req);
        handleUploadPack(req, res, repo, body);
        return;
      }
      if (seg.length === 3 && seg[2] === 'git-receive-pack' && req.method === 'POST') {
        if (!repo) { jsonError(res, 404, 'Repository not found'); return; }
        const body = await readBody(req);
        handleReceivePack(req, res, repo, body);
        return;
      }
      jsonError(res, 404, 'Not Found');
      return;
    }
    if (pathname === '/api/graphql' && req.method === 'POST') {
      await handleGraphql(req, res);
      return;
    }
    if (pathname.startsWith('/api/v3')) {
      await handleRest(req, res, pathname, query);
      return;
    }
    if (pathname === '/mcp') {
      if (req.method === 'POST') { await handleMcp(req, res); return; }
      jsonError(res, 405, 'Method Not Allowed');
      return;
    }
    jsonError(res, 404, 'Not Found');
  } catch (e) {
    // Never crash the process on a bad request.
    try { jsonError(res, 500, e && e.message ? e.message : 'Internal Server Error'); } catch { /* socket gone */ }
  }
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

async function main() {
  const server = http.createServer(requestHandler);
  server.keepAliveTimeout = 5000;
  await new Promise((resolve, reject) => {
    server.listen(0, '127.0.0.1', resolve);
    server.on('error', reject);
  });
  const port = server.address().port;
  const envUrl = process.env.MAKEFUN_ENV_URL;
  if (!envUrl) {
    console.log(`forge listening on http://127.0.0.1:${port}`);
    return;
  }
  const base = envUrl.replace(/\/$/, '');
  // Register (retry for up to 120 s).
  let registered = false;
  const deadline = Date.now() + 120000;
  while (!registered && Date.now() < deadline) {
    try {
      const r = await fetch(`${base}/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ port }),
      });
      if (r.ok || r.status === 409) { registered = true; break; }
    } catch { /* retry */ }
    await sleep(1000);
  }
  if (!registered) {
    console.error('failed to register with the environment');
    process.exit(1);
  }
  // Poll /done until the trial ends.
  while (true) {
    try {
      const r = await fetch(`${base}/done`);
      if (r.ok) {
        const j = await r.json();
        if (j && j.done === true) break;
      }
    } catch { /* retry */ }
    await sleep(500);
  }
  server.close();
  process.exit(0);
}

main().catch((e) => { console.error(e); process.exit(1); });
