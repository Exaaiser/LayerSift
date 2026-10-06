import './style.css';
import { invoke } from '@tauri-apps/api/core';
import { open } from '@tauri-apps/plugin-dialog';
import { openUrl } from '@tauri-apps/plugin-opener';

const PROJECT_URL = 'https://github.com/Exaaiser/LayerSift';
const PROJECT_README_URL = `${PROJECT_URL}/blob/main/README.md`;

if (navigator.userAgent.includes('Windows')) document.documentElement.classList.add('windows');

type Operation = 'resolve' | 'create';
type BackendMode = 'analyze' | 'base64' | 'hash';
type Artifact = { filename?: string; kind?: string; content_hint?: string; origin?: string; steps?: string[]; bytes?: number; preview?: string | null; hex_preview?: string | null };
type Match = { origin?: string; field_type?: string; bytes?: number; hash_candidates?: string[] };
type Response = {
  mode: BackendMode; headline: string; explanation: string; status: string; source: string; inputBytes: number;
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
const settingsMessage = byId<HTMLElement>('settings-message');
const SAVE_DIRECTORY_KEY = 'layersift.saveDirectory';
let operation: Operation = 'resolve';
let filePath: string | null = null;
let current: Response | null = null;
let saveDirectory: string | null = localStorage.getItem(SAVE_DIRECTORY_KEY);
let pages: HTMLElement[] = [];
let pageIndex = 0;

function node(tag: string, className: string, content: string): HTMLElement {
  const element = document.createElement(tag);
  element.className = className;
  element.textContent = content;
  return element;
}
function section(target: HTMLElement, title: string, content: HTMLElement): void {
  const wrap = node('section', 'result-section', '');
  wrap.append(node('h3', '', title), content);
  target.append(wrap);
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
function newPage(): HTMLElement {
  const page = node('div', 'result-page', '');
  pages.push(page);
  return page;
}
function showPage(index: number): void {
  pageIndex = Math.max(0, Math.min(index, pages.length - 1));
  body.replaceChildren(pages[pageIndex]);
  byId('page-count').textContent = `${pageIndex + 1} / ${pages.length}`;
  byId<HTMLButtonElement>('previous-page').disabled = pageIndex === 0;
  byId<HTMLButtonElement>('next-page').disabled = pageIndex === pages.length - 1;
}
function errorPanel(error: unknown): void {
  current = null;
  pages = [];
  byId('result-title').textContent = 'Action failed';
  section(newPage(), 'ERROR', node('p', '', String(error)));
  showPage(0);
  byId<HTMLButtonElement>('save').disabled = true;
  message.textContent = '';
  openPanel();
}
function render(result: Response): void {
  current = result;
  pages = [];
  message.textContent = '';
  message.classList.remove('error');
  byId<HTMLButtonElement>('save').disabled = false;
  byId('result-title').textContent = result.headline;
  const overview = newPage();
  section(overview, 'STATUS', node('p', 'status', result.status));
  section(overview, 'EXPLANATION', node('p', '', result.explanation));
  section(overview, 'SOURCE', node('p', '', `${result.source} · ${result.inputBytes.toLocaleString('en-US')} bytes`));
  if (result.candidates.length) {
    const list = node('div', 'pill-list', '');
    for (const name of result.candidates.slice(0, 8)) list.append(node('span', 'pill', term(name)));
    section(overview, result.mode === 'analyze' ? 'POSSIBLE FORMATS' : 'ALGORITHM', list);
    for (let offset = 8; offset < result.candidates.length; offset += 8) {
      const more = node('div', 'pill-list', '');
      for (const name of result.candidates.slice(offset, offset + 8)) more.append(node('span', 'pill', term(name)));
      section(newPage(), `POSSIBLE FORMATS · ${offset + 1}–${Math.min(offset + 8, result.candidates.length)}`, more);
    }
  }
  const value = result.value || result.preview;
  if (value) {
    const wrap = node('div', '', '');
    const excerpt = value.length > 900 ? `${value.slice(0, 900)}…` : value;
    wrap.append(node('div', 'value', excerpt));
    if (value.length > 900) wrap.append(node('small', 'preview-note', 'Preview only. Save the result for the full value.'));
    if (result.canCopy && result.value) {
      const copy = node('button', 'secondary', 'Copy ↗') as HTMLButtonElement;
      copy.type = 'button';
      copy.addEventListener('click', async () => {
        try { await navigator.clipboard.writeText(result.value || ''); copy.textContent = 'Copied ✓'; }
        catch { copy.textContent = 'Could not copy'; }
      });
      wrap.append(copy);
    }
    section(newPage(), result.mode === 'analyze' ? 'EXTRACTED TEXT' : 'GENERATED VALUE', wrap);
  }
  const artifacts = result.report.artifacts || [];
  if (artifacts.length) {
    for (let offset = 0; offset < artifacts.length; offset += 3) {
      const list = node('div', '', '');
      for (const item of artifacts.slice(offset, offset + 3)) {
        const path = (item.steps || []).map(term).join(' → ');
        const size = item.bytes === undefined ? null : `${item.bytes.toLocaleString('en-US')} bytes`;
        const firstBytes = item.hex_preview ? `First bytes: ${item.hex_preview}${item.bytes && item.bytes > 16 ? ' …' : ''}` : null;
        const description = [item.content_hint ? term(item.content_hint) : null, size, item.origin, path, item.preview || firstBytes].filter(Boolean).join(' · ');
        list.append(detail(item.filename || item.kind || 'Content', description));
      }
      section(newPage(), `FOUND CONTENT · ${offset + 1}–${Math.min(offset + 3, artifacts.length)} OF ${artifacts.length}`, list);
    }
  }
  const matches = result.report.matches || [];
  if (matches.length) {
    for (let offset = 0; offset < matches.length; offset += 4) {
      const list = node('div', '', '');
      for (const item of matches.slice(offset, offset + 4)) {
        const kinds = item.hash_candidates?.length ? ' · possible hash: ' + item.hash_candidates.map(term).join(', ') : '';
        list.append(detail(item.origin || 'Location', term(item.field_type || 'Field') + ' · ' + (item.bytes || 0) + ' bytes' + kinds));
      }
      section(newPage(), `SCANNED FIELDS · ${offset + 1}–${Math.min(offset + 4, matches.length)} OF ${matches.length}`, list);
    }
  }
  const notes = result.report.notes || [];
  for (let offset = 0; offset < notes.length; offset += 2) {
    section(newPage(), `NOTES · ${offset + 1}–${Math.min(offset + 2, notes.length)} OF ${notes.length}`, node('p', '', notes.slice(offset, offset + 2).join('\n\n')));
  }
  showPage(0);
  openPanel();
}
function showView(view: 'menu' | 'settings'): void {
  byId('view-menu').hidden = view !== 'menu';
  byId('view-settings').hidden = view !== 'settings';
  for (const name of ['menu', 'settings'] as const) {
    const tab = byId<HTMLButtonElement>('tab-' + name);
    tab.classList.toggle('active', view === name);
    tab.setAttribute('aria-selected', view === name ? 'true' : 'false');
  }
  closePanel();
}
function updateInputPlaceholder(): void {
  const method = byId<HTMLSelectElement>('method').value;
  entry.placeholder = operation === 'resolve' ? 'Paste text or encoded data here…' : method === 'base64' ? 'Enter text to encode as Base64…' : 'Enter text to hash…';
}
function setOperation(next: Operation): void {
  operation = next;
  for (const button of document.querySelectorAll<HTMLButtonElement>('.mode')) {
    const selected = button.dataset.operation === next;
    button.classList.toggle('active', selected);
    button.setAttribute('aria-selected', selected ? 'true' : 'false');
  }
  byId('method-row').hidden = next !== 'create';
  updateInputPlaceholder();
  byId('run').firstChild!.textContent = next === 'resolve' ? 'Resolve ' : 'Create ';
}
function clearFile(): void {
  filePath = null;
  byId('file-selection').hidden = true;
  byId('input-hint').hidden = false;
}
function setSaveDirectory(path: string | null): void {
  saveDirectory = path;
  if (path) localStorage.setItem(SAVE_DIRECTORY_KEY, path);
  else localStorage.removeItem(SAVE_DIRECTORY_KEY);
  const display = byId('save-path');
  display.textContent = path || 'Documents / LayerSift';
  display.title = path || 'Documents / LayerSift';
  settingsMessage.textContent = path ? 'Future saves will go to this folder.' : 'Using the default Documents folder.';
  settingsMessage.classList.remove('error');
}
function settingsError(error: unknown): void {
  settingsMessage.textContent = String(error);
  settingsMessage.classList.add('error');
}
async function run(): Promise<void> {
  const button = byId<HTMLButtonElement>('run');
  if (button.disabled) return;
  button.disabled = true;
  const label = button.firstChild!.textContent;
  button.firstChild!.textContent = 'Working ';
  try {
    const method = byId<HTMLSelectElement>('method').value;
    const mode: BackendMode = operation === 'resolve' ? 'analyze' : method === 'base64' ? 'base64' : 'hash';
    const response = await invoke<Response>('run_action', { request: {
      mode,
      text: filePath ? null : entry.value,
      filePath,
      algorithm: mode === 'hash' ? method : null,
      caesarShift: null,
      xorKey: null,
      zipPassword: null,
      autoXor: mode === 'analyze' ? true : null,
    } });
    render(response);
  } catch (error) { errorPanel(error); }
  finally { button.disabled = false; button.firstChild!.textContent = label; }
}

byId('tab-menu').addEventListener('click', () => showView('menu'));
byId('tab-settings').addEventListener('click', () => showView('settings'));
byId('previous-page').addEventListener('click', () => showPage(pageIndex - 1));
byId('next-page').addEventListener('click', () => showPage(pageIndex + 1));
setSaveDirectory(saveDirectory);
byId('choose-output').addEventListener('click', async () => {
  try {
    const selected = await open({ directory: true, multiple: false, canCreateDirectories: true, title: 'Choose where to save analyses', ...(saveDirectory ? { defaultPath: saveDirectory } : {}) });
    if (typeof selected === 'string') setSaveDirectory(selected);
  } catch (error) { settingsError(error); }
});
byId('new-output').addEventListener('click', () => {
  byId('new-folder-row').hidden = false;
  byId<HTMLInputElement>('new-folder-name').focus();
});
byId('cancel-folder').addEventListener('click', () => { byId('new-folder-row').hidden = true; });
byId('create-folder').addEventListener('click', async () => {
  const name = byId<HTMLInputElement>('new-folder-name').value.trim();
  try {
    const path = await invoke<string>('create_output_folder', { parentPath: saveDirectory, name });
    setSaveDirectory(path);
    byId<HTMLInputElement>('new-folder-name').value = '';
    byId('new-folder-row').hidden = true;
  } catch (error) { settingsError(error); }
});
byId('new-folder-name').addEventListener('keydown', event => {
  if (event.key === 'Enter') { event.preventDefault(); byId<HTMLButtonElement>('create-folder').click(); }
});
byId('reset-output').addEventListener('click', () => setSaveDirectory(null));
for (const button of document.querySelectorAll<HTMLButtonElement>('.mode')) {
  button.addEventListener('click', () => setOperation(button.dataset.operation as Operation));
}
byId('method').addEventListener('change', updateInputPlaceholder);
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
  try { message.textContent = 'Saved: ' + await invoke<string>('save_result', { destination: saveDirectory }); }
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
