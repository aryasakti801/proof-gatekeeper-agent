import fs from 'node:fs';
import path from 'node:path';

export function normalizeRef(value) {
  if (value == null) return '';
  let s = String(value).trim().toLowerCase();
  if (s.startsWith('0x')) s = s.slice(2);
  return s;
}

export class SeenSet {
  constructor(filePath) {
    this.filePath = filePath;
    this.ids = new Set();
    this.taskCache = new Map();
    this._load();
  }

  _load() {
    try {
      const raw = fs.readFileSync(this.filePath, 'utf8');
      const data = JSON.parse(raw);
      for (const id of data.proof_tx ?? []) this.ids.add(normalizeRef(id));
      for (const [taskId, body] of Object.entries(data.tasks ?? {})) {
        this.taskCache.set(taskId, body);
      }
    } catch (e) {
      if (e.code !== 'ENOENT') throw e;
    }
  }

  _save() {
    const dir = path.dirname(this.filePath);
    fs.mkdirSync(dir, { recursive: true });
    const tmp = this.filePath + '.tmp';
    const data = {
      proof_tx: [...this.ids],
      tasks: Object.fromEntries(this.taskCache),
    };
    fs.writeFileSync(tmp, JSON.stringify(data, null, 2));
    fs.renameSync(tmp, this.filePath);
  }

  hasProofTx(ref) {
    const id = normalizeRef(ref);
    return id ? this.ids.has(id) : false;
  }

  rememberApproval(ref) {
    const id = normalizeRef(ref);
    if (!id) return;
    this.ids.add(id);
    this._save();
  }

  getTask(taskId) {
    return this.taskCache.get(taskId);
  }

  rememberTask(taskId, body) {
    this.taskCache.set(taskId, body);
    this._save();
  }
}
