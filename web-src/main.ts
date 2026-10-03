import './style.css';
import { invoke } from '@tauri-apps/api/core';
import { open } from '@tauri-apps/plugin-dialog';
import { openUrl } from '@tauri-apps/plugin-opener';

const PROJECT_URL = 'https://github.com/Exaaiser/LayerSift';
const PROJECT_README_URL = `${PROJECT_URL}/blob/main/README.md`;

type Mode = 'analyze' | 'base64' | 'hash';
type Artifact = { filename?: string; kind?: string; content_hint?: string; origin?: string; steps?: string[]; bytes?: number; preview?: string | null; hex_preview?: string | null };
type Match = { origin?: string; field_type?: string; bytes?: number; hash_candidates?: string[] };
type Response = {
  mode: Mode; headline: string; explanation: string; status: string; source: string; inputBytes: number;
  candidates: string[]; value: string | null; preview?: string;
  canCopy: boolean; report: { artifacts?: Artifact[]; matches?: Match[]; notes?: string[] };
};

function byId<T extends HTMLElement>(id: string): T {
  const element = document.getElementById(id);
  if (!element) throw new Error('Missing UI element: ' + id);
  return element as T;
}
const entry = byId<HTMLTextAreaElement>('entry');
const panel = byId<HTMLElement>('result-panel');
const body = byId<HTMLElement>('result-body');
const scrim = byId<HTMLElement>('scrim');
const message = byId<HTMLElement>('save-message');
let mode: Mode = 'analyze';
let filePath: string | null = null;
let current: Response | null = null;

function node(tag: string, className: string, content: string): HTMLElement {
  const element = document.createElement(tag);
  element.className = className;
  element.textContent = content;
  return element;
}
function section(title: string, content: HTMLElement): void {
  const wrap = node('section', 'result-section', '');
  wrap.append(node('h3', '', title), content);
  body.append(wrap);
}
function detail(title: string, description: string): HTMLElement {
  const wrap = node('div', 'detail', '');
  wrap.append(node('strong', '', title), node('small', '', description));
  return wrap;
}
function term(value: string): string {
  const dictionary: Record<string, string> = {
    'JSON string': 'JSON field', 'SQL string': 'SQL field', 'text token': 'Text token',
    'base64 decode': 'Base64 decode', 'hex decode': 'Hex decode',
    'gzip decompress': 'gzip decompression', 'zlib decompress': 'zlib decompression',
    'possible email address': 'Possible email address', 'text': 'Text',
    'binary data': 'Binary data', 'zip member': 'ZIP member',
    sha256: 'SHA-256', sha512: 'SHA-512', sha1: 'SHA-1', md5: 'MD5',
    'sha3-256': 'SHA3-256', 'sha3-512': 'SHA3-512', blake2s: 'BLAKE2s', blake2b: 'BLAKE2b',
  };
  return dictionary[value] || value;
}
function openPanel(): void {
  scrim.hidden = false;
  panel.classList.add('open');
  panel.setAttribute('aria-hidden', 'false');
}
function closePanel(): void {
  panel.classList.remove('open');
  panel.setAttribute('aria-hidden', 'true');
  scrim.hidden = true;
}
function errorPanel(error: unknown): void {
  current = null;
  body.replaceChildren();
  byId('result-title').textContent = 'Action failed';
  section('ERROR', node('p', '', String(error)));
  byId<HTMLButtonElement>('save').disabled = true;
  message.textContent = '';
  openPanel();
}
function render(result: Response): void {
  current = result;
  body.replaceChildren();
  message.textContent = '';
  message.classList.remove('error');
  byId<HTMLButtonElement>('save').disabled = false;
  byId('result-title').textContent = result.headline;
  section('STATUS', node('p', 'status', result.status));
  section('EXPLANATION', node('p', '', result.explanation));
  section('SOURCE', node('p', '', `${result.source} · ${result.inputBytes.toLocaleString('en-US')} bytes`));
  if (result.candidates.length) {
    const list = node('div', 'pill-list', '');
    for (const name of result.candidates) list.append(node('span', 'pill', term(name)));
    section(result.mode === 'analyze' ? 'POSSIBLE FORMATS' : 'ALGORITHM', list);
  }
  const value = result.value || result.preview;
  if (value) {
    const wrap = node('div', '', '');
    wrap.append(node('div', 'value', value));
    if (result.canCopy && result.value) {
      const copy = node('button', 'secondary', 'Copy ↗') as HTMLButtonElement;
      copy.type = 'button';
      copy.addEventListener('click', async () => {
        try { await navigator.clipboard.writeText(result.value || ''); copy.textContent = 'Copied ✓'; }
        catch { copy.textContent = 'Could not copy'; }
      });
      wrap.append(copy);
    }
    section(result.mode === 'analyze' ? 'EXTRACTED TEXT' : 'GENERATED VALUE', wrap);
  }
  const artifacts = result.report.artifacts || [];
  if (artifacts.length) {
    const list = node('div', '', '');
    for (const item of artifacts.slice(0, 12)) {
      const path = (item.steps || []).map(term).join(' → ');
      const size = item.bytes === undefined ? null : `${item.bytes.toLocaleString('en-US')} bytes`;
      const firstBytes = item.hex_preview ? `First bytes: ${item.hex_preview}${item.bytes && item.bytes > 16 ? ' …' : ''}` : null;
      const description = [item.content_hint ? term(item.content_hint) : null, size, item.origin, path, item.preview || firstBytes].filter(Boolean).join(' · ');
      list.append(detail(item.filename || item.kind || 'Content', description));
    }
    section('FOUND CONTENT · ' + artifacts.length, list);
  }
  const matches = result.report.matches || [];
  if (matches.length) {
    const list = node('div', '', '');
    for (const item of matches.slice(0, 8)) {
      const kinds = item.hash_candidates?.length ? ' · possible hash: ' + item.hash_candidates.map(term).join(', ') : '';
      list.append(detail(item.origin || 'Location', term(item.field_type || 'Field') + ' · ' + (item.bytes || 0) + ' bytes' + kinds));
    }
    section('SCANNED FIELDS · ' + matches.length, list);
  }
  const notes = result.report.notes || [];
  if (notes.length) section('NOTES', node('p', '', notes.slice(0, 5).join(' · ')));
  openPanel();
}
function showView(view: 'menu' | 'advanced'): void {
  byId('view-menu').hidden = view !== 'menu';
  byId('view-advanced').hidden = view !== 'advanced';
  for (const name of ['menu', 'advanced'] as const) {
    const tab = byId<HTMLButtonElement>('tab-' + name);
    tab.classList.toggle('active', view === name);
    tab.setAttribute('aria-selected', view === name ? 'true' : 'false');
  }
  closePanel();
}
function setMode(next: Mode): void {
  mode = next;
  for (const button of document.querySelectorAll<HTMLButtonElement>('.mode')) {
    const selected = button.dataset.mode === next;
    button.classList.toggle('active', selected);
    button.setAttribute('aria-selected', selected ? 'true' : 'false');
  }
  byId('algorithm-row').hidden = next !== 'hash';
  entry.placeholder = next === 'analyze' ? 'Paste text or encoded data here…' : next === 'base64' ? 'Enter text to encode as Base64…' : 'Enter text to hash…';
  byId('run').firstChild!.textContent = next === 'analyze' ? 'Analyze ' : 'Create ';
}
function clearFile(): void {
  filePath = null;
  byId('file-selection').hidden = true;
  byId('input-hint').hidden = false;
}
async function run(): Promise<void> {
  const button = byId<HTMLButtonElement>('run');
  if (button.disabled) return;
  const caesarField = byId<HTMLInputElement>('caesar').value.trim();
  const caesarShift = caesarField ? Number(caesarField) : null;
  if (caesarShift !== null && (!Number.isInteger(caesarShift) || caesarShift < 0 || caesarShift > 25)) {
    errorPanel('Caesar shift must be a whole number from 0 to 25.');
    return;
  }
  button.disabled = true;
  const label = button.firstChild!.textContent;
  button.firstChild!.textContent = 'Working ';
  try {
    const response = await invoke<Response>('run_action', { request: {
      mode,
      text: filePath ? null : entry.value,
      filePath,
      algorithm: mode === 'hash' ? byId<HTMLSelectElement>('algorithm').value : null,
      caesarShift: mode === 'analyze' ? caesarShift : null,
      xorKey: mode === 'analyze' ? byId<HTMLInputElement>('xor-key').value : null,
      zipPassword: mode === 'analyze' ? byId<HTMLInputElement>('zip-password').value : null,
      autoXor: mode === 'analyze' ? byId<HTMLInputElement>('auto-xor').checked : null,
    } });
    render(response);
  } catch (error) { errorPanel(error); }
  finally { button.disabled = false; button.firstChild!.textContent = label; }
}

byId('tab-menu').addEventListener('click', () => showView('menu'));
byId('tab-advanced').addEventListener('click', () => showView('advanced'));
for (const button of document.querySelectorAll<HTMLButtonElement>('.mode')) {
  button.addEventListener('click', () => setMode(button.dataset.mode as Mode));
}
byId('choose-file').addEventListener('click', async () => {
  try {
    const selected = await open({ multiple: false, directory: false, title: 'Choose a file' });
    if (typeof selected !== 'string') return;
    filePath = selected;
    entry.value = '';
    byId('file-name').textContent = selected.split(/[\\/]/).pop() || selected;
    byId('file-selection').hidden = false;
    byId('input-hint').hidden = true;
  } catch (error) { errorPanel(error); }
});
byId('remove-file').addEventListener('click', clearFile);
entry.addEventListener('input', () => { if (entry.value && filePath) clearFile(); });
byId('run').addEventListener('click', () => { void run(); });
byId('close-result').addEventListener('click', closePanel);
scrim.addEventListener('click', closePanel);
byId('save').addEventListener('click', async () => {
  if (!current) return;
  const button = byId<HTMLButtonElement>('save');
  button.disabled = true;
  message.textContent = 'Saving…';
  message.classList.remove('error');
  try { message.textContent = 'Saved: ' + await invoke<string>('save_to_documents'); }
  catch (error) { message.textContent = String(error); message.classList.add('error'); }
  finally { button.disabled = false; }
});
byId('github-link').addEventListener('click', async () => {
  try { await openUrl(PROJECT_URL); } catch (error) { errorPanel(error); }
});
byId('readme-link').addEventListener('click', async () => {
  try {
    await openUrl(PROJECT_README_URL);
  } catch (error) { errorPanel(error); }
});
document.addEventListener('keydown', event => {
  if (event.key === 'Escape') closePanel();
  if ((event.metaKey || event.ctrlKey) && event.key === 'Enter' && !byId('view-menu').hidden) { event.preventDefault(); void run(); }
});
