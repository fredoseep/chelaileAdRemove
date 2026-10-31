'use strict';
// v5: defer unpacking observers until DexHelper load, after LSPatch bootstrap.
// Only writes cfg+0x17c |= 0x840. No DEX dump or check-result replacement.
const POLICY_MASK = 0x840;
const libc = Process.getModuleByName('libc.so');
let logWrite = null;
try {
  logWrite = new NativeFunction(Process.getModuleByName('liblog.so')
    .getExportByName('__android_log_write'), 'int', ['int', 'pointer', 'pointer']);
} catch (_) {}
const tag = Memory.allocUtf8String('CLL.Flag');
function log(message, error) {
  if (logWrite) logWrite(error ? 6 : 4, tag, Memory.allocUtf8String(message));
  else console.log('CLL.Flag: ' + message);
}
function bytes(p, n) {
  return Array.from(new Uint8Array(p.readByteArray(n)),
    x => x.toString(16).padStart(2, '0')).join('');
}
function readable(p, n) {
  const r = Process.findRangeByAddress(p);
  return r && r.protection.includes('r') && p.add(n).compare(r.base.add(r.size)) <= 0;
}
const signatures = [
  [0x1caf0, 'b8c9ff9740fcff37'], [0x1f4d4, 'e8af40b948023037'],
  [0x1f534, '8af380524bd4b672'], [0x1f554, '40011fd688a91691'],
  [0x20cd0, '080800f008d946f9'], [0x20cd8, '080140f908f54539'],
  [0x20ce0, '88551837aa699152'], [0x20cec, '8b698152000080d2'],
  [0x20cfc, 'e8030aaae9030baa'], [0x21790, '00e4006fe1030e91']
];
function matches(base) {
  if (!readable(base, 4) || base.readU32() !== 0x464c457f) return false;
  // The checkpoint's entry instructions are temporarily replaced by our own
  // Interceptor. They were checked before installation; check them again after
  // cleanup restores them. Never treat our trampoline as a new app version.
  const ownCheckpoint = checkpointHook && imageBase && base.compare(imageBase) === 0;
  return signatures.every(([off, expected]) =>
    (ownCheckpoint && off >= 0x20cd0 && off < 0x20ce8)
    || (readable(base.add(off), 8) && bytes(base.add(off), 8) === expected));
}
function applyPolicy(base, reason) {
  if (!matches(base)) throw new Error('Image fingerprint mismatch');
  const slot = base.add(0x123db0);
  if (!readable(slot, 8)) throw new Error('Unreadable config slot');
  const root = slot.readPointer();
  if (!readable(root, 8)) throw new Error('Unreadable config root');
  const cfg = root.readPointer(), field = cfg.add(0x17c);
  const cr = Process.findRangeByAddress(field);
  if (!readable(cfg, 0x180) || !cr || !cr.protection.includes('w')
      || cfg.compare(base.add(0x11f910)) < 0
      || cfg.add(0x180).compare(base.add(0x147d60)) > 0)
    throw new Error('Unexpected config layout');
  const before = field.readU32(), after = (before | POLICY_MASK) >>> 0;
  field.writeU32(after);
  if (field.readU32() !== after) throw new Error('Write verification failed');
  log('pid=' + Process.id + ' flag=' + field + ' ' + before + ' -> ' + after
    + ' mask=0x840 via=' + reason);
}
if (Process.arch !== 'arm64') throw new Error('CLL.Flag requires arm64');
let forkHook = null, checkpointHook = null, imageBase = null, installing = false;
const watchers = [];
function cleanup() {
  // Remove callbacks before fork, or after the no-fork checkpoint fires.
  if (forkHook) { forkHook.detach(); forkHook = null; }
  if (checkpointHook) { checkpointHook.detach(); checkpointHook = null; }
  for (const h of watchers.splice(0)) h.detach();
  Interceptor.flush();
}
function armCheckpoint(base, reason) {
  if (imageBase || installing) return;
  try {
    if (!matches(base)) return;
    installing = true;
    // This exact instruction reloads cfg just before the known 0xb4c branch.
    // Do not skip the check; update its existing policy bit before it reads cfg.
    checkpointHook = Interceptor.attach(base.add(0x20cd0), {
      onEnter() {
        cleanup();
        try { applyPolicy(base, 'before-b4c'); }
        catch (e) { log('Policy update failed: ' + e, true); }
      }
    });
    imageBase = base;
    // The image has been located; broad startup observers are no longer needed.
    for (const h of watchers.splice(0)) h.detach();
    log('pid=' + Process.id + ' no-fork checkpoint armed base=' + base + ' source=' + reason);
  } catch (e) {
    log('Checkpoint setup failed: ' + e, true);
  } finally { installing = false; }
}
function scanImages(reason) {
  if (imageBase || installing) return;
  for (const r of Process.enumerateRanges({protection: 'r-x', coalesce: false})) {
    if (r.size >= 0x110000 && r.size <= 0x200000) {
      armCheckpoint(r.base, reason);
      if (imageBase) return;
    }
  }
}
// Existing main-process route, unchanged in purpose. No child onLeave callback.
forkHook = Interceptor.attach(libc.getExportByName('fork'), {
  onEnter() {
    const caller = this.returnAddress, r = Process.findRangeByAddress(caller);
    if (!r || caller.sub(r.base).toString() !== '0x1caf4') return;
    if (!matches(r.base)) return;
    cleanup();
    try { applyPolicy(r.base, 'fork'); }
    catch (e) { log('Policy update failed: ' + e, true); }
  }
});
// Do not observe mprotect during LSPatch bootstrap: its hook installation can
// temporarily change libc.open while a Frida range query opens /proc/PID/maps.
// Install this observer only once the original app starts loading DexHelper.
const mprotectAddress = libc.getExportByName('mprotect');
let unpackObserverStarted = false;
function startUnpackObserver() {
  if (unpackObserverStarted || imageBase) return;
  unpackObserverStarted = true;
  watchers.push(Interceptor.attach(mprotectAddress, {
    onEnter(args) {
      this.candidate = !imageBase && !installing && (args[2].toInt32() & 4) !== 0
        ? args[0] : null;
    },
    onLeave(retval) {
      if (!this.candidate || retval.toInt32() !== 0 || imageBase || installing) return;
      try { armCheckpoint(this.candidate, 'DexHelper-mprotect'); }
      catch (_) {}
    }
  }));
  log('pid=' + Process.id + ' DexHelper load entered; unpack observer enabled');
}
try {
  const libdl = Process.getModuleByName('libdl.so');
  watchers.push(Interceptor.attach(libdl.getExportByName('android_dlopen_ext'), {
    onEnter(args) {
      try { this.target = /libDexHelper\.so$/.test(args[0].readUtf8String() || ''); }
      catch (_) { this.target = false; }
      if (this.target) {
        try { startUnpackObserver(); }
        catch (e) { log('Unpack observer setup failed: ' + e, true); }
      }
    },
    onLeave() {
      if (this.target && !imageBase) {
        try { scanImages('DexHelper-dlopen'); }
        catch (e) { log('Image scan failed: ' + e, true); }
      }
    }
  }));
} catch (e) { log('dlopen observer unavailable: ' + e, true); }
// No initial map scan and no early mprotect observer.
log('ready v5 pid=' + Process.id + '; waiting for DexHelper load');
