#!/usr/bin/env python3
"""Ubuntu/Linux ARM64-target packager. Python 3.12+, Java 21 (auto JRE fallback).
Preserves pristine origin inside LSPatch; no target APK or module code is shipped.
"""
import argparse
import hashlib
import json
import lzma
import os
from pathlib import Path
import platform
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import time
import urllib.request
import zipfile
import zlib

ROOT = Path(__file__).resolve().parent
TOOLS = ROOT / 'tools'
URLS = {
    'lspatch.jar': 'https://github.com/JingMatrix/LSPatch/releases/download/v1.2/lspatch-v1.2-487-release.jar',
    'apktool.jar': 'https://github.com/iBotPeaches/Apktool/releases/download/v2.11.1/apktool_2.11.1.jar',
    'uber-apk-signer.jar': 'https://github.com/patrickfav/uber-apk-signer/releases/download/v1.3.0/uber-apk-signer-1.3.0.jar',
    'gadget.so.xz': 'https://github.com/frida/frida/releases/download/17.15.5/frida-gadget-17.15.5-android-arm64.so.xz',
}


def say(s):
    print(s, flush=True)


def fetch(url, path):
    if path.is_file() and path.stat().st_size:
        return path
    say('下载：' + path.name)
    part = path.with_name(path.name + '.part')
    for attempt in range(3):
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'CLL-Pack/1.0'})
            with urllib.request.urlopen(req, timeout=60) as src, part.open('wb') as dst:
                shutil.copyfileobj(src, dst, 1024 * 1024)
            part.replace(path)
            return path
        except Exception:
            part.unlink(missing_ok=True)
            if attempt == 2:
                raise
            time.sleep(1)


def run(args, log=None):
    args = [str(x) for x in args]
    if log:
        with log.open('a', encoding='utf-8') as f:
            f.write('\n$ ' + ' '.join(args) + '\n')
            f.flush()
            result = subprocess.run(args, stdout=f, stderr=subprocess.STDOUT)
        if result.returncode:
            lines = log.read_text(errors='replace').splitlines()
            say('\n'.join(lines[-45:]))
            raise RuntimeError(f'工具执行失败（{result.returncode}），完整日志：{log}')
    else:
        subprocess.run(args, check=True)


def java_major(java):
    try:
        p = subprocess.run([str(java), '-version'], capture_output=True, text=True)
        m = re.search(r'version "(?:1\.)?(\d+)', p.stderr + p.stdout)
        return int(m.group(1)) if m else 0
    except OSError:
        return 0


def get_java():
    choices = [os.environ.get('CLL_JAVA'), shutil.which('java')]
    for env in ('JAVA_HOME', 'STUDIO_JDK', 'JDK_HOME'):
        if os.environ.get(env):
            choices.append(str(Path(os.environ[env]) / 'bin/java'))
    for base in [Path('/opt'), Path.home() / 'android-studio', Path.home() / 'app',
                 Path.home() / '.jdks', Path('/usr/lib/jvm'), TOOLS / 'jre21']:
        if base.is_dir():
            choices += [str(p) for pat in ('*/bin/java', '*/jbr/bin/java', 'jbr/bin/java',
                                           '*/*/jbr/bin/java') for p in base.glob(pat)]
    for choice in choices:
        if choice and java_major(choice) >= 21:
            return Path(choice)
    # Portable JRE; no apt/sudo and no changes to system Java.
    if platform.system() != 'Linux' or platform.machine() not in ('x86_64', 'aarch64'):
        raise RuntimeError('请安装 Java 21，或设置 CLL_JAVA=/绝对路径/bin/java')
    arch = 'x64' if platform.machine() == 'x86_64' else 'aarch64'
    say('未找到 Java 21，准备下载便携 JRE 21。')
    req = urllib.request.Request(
        'https://api.github.com/repos/adoptium/temurin21-binaries/releases/latest',
        headers={'User-Agent': 'CLL-Pack/1.0'})
    with urllib.request.urlopen(req, timeout=60) as response:
        release = json.load(response)
    asset = next(a for a in release['assets']
                 if a['name'].startswith(f'OpenJDK21U-jre_{arch}_linux_hotspot_')
                 and a['name'].endswith('.tar.gz'))
    archive = fetch(asset['browser_download_url'], TOOLS / asset['name'])
    destination = TOOLS / 'jre21'
    destination.mkdir(exist_ok=True)
    with tarfile.open(archive) as t:
        t.extractall(destination, filter='data')
    java = next(destination.glob('*/bin/java'))
    if java_major(java) < 21:
        raise RuntimeError('下载的 JRE 无法启动；请设置 CLL_JAVA。')
    return java


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for b in iter(lambda: f.read(1024 * 1024), b''):
            h.update(b)
    return h.hexdigest()


def is_module(path):
    with zipfile.ZipFile(path) as z:
        names = set(z.namelist())
        if 'AndroidManifest.xml' not in names:
            raise ValueError(f'不是 APK：{path}')
        return bool({'assets/xposed_init', 'META-INF/xposed/java_init.list'} & names)


def choose_inputs(args):
    if args.original or args.module:
        if not args.original or not args.module:
            raise ValueError('--original 和 --module 必须一起指定')
        original, module = args.original.resolve(), args.module.resolve()
    else:
        apks = sorted(p for p in ROOT.iterdir() if p.is_file() and p.suffix.lower() == '.apk')
        modules = [p for p in apks if is_module(p)]
        originals = [p for p in apks if p not in modules]
        if len(modules) != 1 or len(originals) != 1:
            raise ValueError('请在脚本同目录放一个原包和一个模块 APK；'
                             '或使用 --original 原包.apk --module 模块.apk')
        original, module = originals[0], modules[0]
    if original == module or is_module(original) or not is_module(module):
        raise ValueError('原包/模块识别失败：模块需要 assets/xposed_init 或 java_init.list')
    with zipfile.ZipFile(original) as z:
        if any(n.startswith('assets/lspatch/') for n in z.namelist()):
            raise ValueError('输入已经是 LSPatch 包，请换未修改原包')
        if not any(n.startswith('lib/arm64-v8a/') for n in z.namelist()):
            raise ValueError('原包没有 ARM64 库，本脚本仅支持已分析的 ARM64 构建')
    return original, module


BOOTSTRAP = '''.class public final Lcll/boot/FlagBootstrap;
.super Ljava/lang/Object;

.method public static start()V
    .locals 1
    const-string v0, "cllflag"
    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
    return-void
.end method
'''


def binary_manifest_info(blob):
    # Minimal binary XML reader: string pool + start-element attributes only.
    # The manifest is read for validation and is never rewritten as text.
    strings = []
    result = {}
    u16 = lambda off: struct.unpack_from('<H', blob, off)[0]
    u32 = lambda off: struct.unpack_from('<I', blob, off)[0]
    def length8(off):
        n = blob[off]
        return (((n & 127) << 8) | blob[off + 1], off + 2) if n & 128 else (n, off + 1)
    def length16(off):
        n = u16(off)
        return (((n & 32767) << 16) | u16(off + 2), off + 4) if n & 32768 else (n, off + 2)
    off = u16(2)
    while off < len(blob):
        kind, hs, size = struct.unpack_from('<HHI', blob, off)
        if size < hs or size == 0 or off + size > len(blob):
            raise ValueError('无效的二进制 manifest chunk')
        if kind == 1:
            count, flags, start = u32(off + 8), u32(off + 16), u32(off + 20)
            for i in range(count):
                at = off + start + u32(off + hs + i * 4)
                if flags & 0x100:
                    _, at = length8(at)
                    length, at = length8(at)
                    strings.append(blob[at:at + length].decode('utf-8'))
                else:
                    length, at = length16(at)
                    strings.append(blob[at:at + length * 2].decode('utf-16le'))
        elif kind == 0x102:
            tag = strings[u32(off + 20)]
            if tag in ('manifest', 'application'):
                attr_start, attr_size, attr_count = u16(off + 24), u16(off + 26), u16(off + 28)
                for i in range(attr_count):
                    at = off + 16 + attr_start + i * attr_size
                    key = strings[u32(at + 4)]
                    data_type, data = blob[at + 15], u32(at + 16)
                    result[key] = strings[data] if data_type == 3 else data
        off += size
    return result


def inject(decoded):
    manifest = decoded / 'AndroidManifest.xml'
    info = binary_manifest_info(manifest.read_bytes())
    if info.get('package') != 'com.ygkj.chelaile.standard':
        raise ValueError('原包包名不是 com.ygkj.chelaile.standard')
    factory = info.get('appComponentFactory')
    if not factory or 'lspatch' not in factory.lower():
        raise ValueError('未找到预期的 LSPatch AppComponentFactory，停止注入')
    if not info.get('extractNativeLibs'):
        raise ValueError('extractNativeLibs 没有启用，停止注入')
    relative = Path(*factory.split('.')).with_suffix('.smali')
    hits = [d / relative for d in decoded.glob('smali*') if (d / relative).is_file()]
    if len(hits) != 1:
        raise ValueError('AppComponentFactory smali 不唯一或缺失：' + factory)
    target = hits[0]
    smali = target.read_text()
    call = '    invoke-static {}, Lcll/boot/FlagBootstrap;->start()V\n'
    clinit = re.search(r'^\.method[^\n]* <clinit>\(\)V[^\n]*\n(.*?)^\.end method',
                       smali, re.M | re.S)
    if clinit:
        body = clinit.group(1)
        registers = re.search(r'^\s*\.(?:locals|registers)\s+\d+[^\n]*\n', body, re.M)
        if not registers:
            raise ValueError('静态初始化没有寄存器声明，停止注入')
        at = clinit.start(1) + registers.end()
        smali = smali[:at] + call + smali[at:]
    else:
        smali += '\n.method static constructor <clinit>()V\n    .locals 0\n' + call \
            + '    return-void\n.end method\n'
    target.write_text(smali)
    smali_root = next(d for d in decoded.glob('smali*') if target.is_relative_to(d))
    helper = smali_root / 'cll/boot/FlagBootstrap.smali'
    if helper.exists():
        raise ValueError('Bootstrap 类名冲突')
    helper.parent.mkdir(parents=True, exist_ok=True)
    helper.write_text(BOOTSTRAP)
    lib = decoded / 'lib'
    lib.mkdir(exist_ok=True)
    for child in lib.iterdir():
        if child.is_dir() and child.name != 'arm64-v8a':
            shutil.rmtree(child)
    arm = lib / 'arm64-v8a'
    arm.mkdir(exist_ok=True)
    shutil.copy2(TOOLS / 'gadget.so', arm / 'libcllflag.so')
    shutil.copy2(ROOT / 'flag.js', arm / 'libcllflag.script.so')
    (arm / 'libcllflag.config.so').write_text(json.dumps({
        'interaction': {'type': 'script', 'path': 'libcllflag.script.so', 'on_change': 'ignore'},
        'runtime': 'qjs', 'teardown': 'minimal', 'code_signing': 'optional'
    }, indent=2))
    return factory


def is_direct_library(name):
    # LSPatch calls System.load("base.apk!/assets/lspatch/so/.../liblspatch.so").
    # These assets have the SAME page-alignment requirement as lib/*.so.
    return name.endswith('.so') and (name.startswith('lib/')
                                     or name.startswith('assets/lspatch/so/'))


def align_apk(source, destination):
    # Rebuild ZIP before signing: stored native libraries get 16 KiB alignment,
    # other stored entries 4 bytes. No signing-block data is copied.
    with zipfile.ZipFile(source) as src, zipfile.ZipFile(destination, 'w') as dst:
        for old in src.infolist():
            if re.match(r'^META-INF/[^/]+\.(?:SF|RSA|DSA|EC|MF)$', old.filename, re.I):
                continue
            data = src.read(old)
            info = zipfile.ZipInfo(old.filename, old.date_time)
            info.compress_type = zipfile.ZIP_STORED if is_direct_library(old.filename) else old.compress_type
            info.external_attr = old.external_attr
            info.create_system = old.create_system
            # Keep Unix/UTF-8 naming decisions consistent with zipfile's encoder.
            filename = info._encodeFilenameFlags()[0]
            alignment = 16384 if is_direct_library(old.filename) else 4
            if info.compress_type == zipfile.ZIP_STORED:
                start = dst.fp.tell() + 30 + len(filename)
                extra_size = (-start) % alignment
                if extra_size:
                    if extra_size < 4:
                        extra_size += alignment
                    info.extra = struct.pack('<HH', 0xd935, extra_size - 4) + bytes(extra_size - 4)
            dst.writestr(info, data)
    check_alignment(destination)


def check_alignment(path):
    with path.open('rb') as f, zipfile.ZipFile(path) as z:
        for info in z.infolist():
            if is_direct_library(info.filename) and info.compress_type != zipfile.ZIP_STORED:
                raise ValueError('直接加载的原生库不能压缩：' + info.filename)
            if info.compress_type != zipfile.ZIP_STORED:
                continue
            f.seek(info.header_offset + 26)
            n, e = struct.unpack('<HH', f.read(4))
            offset = info.header_offset + 30 + n + e
            align = 16384 if is_direct_library(info.filename) else 4
            if offset % align:
                raise ValueError('ZIP 对齐检查失败：' + info.filename)


def zip_bytes(z, name):
    info = z.getinfo(name) if isinstance(name, str) else name
    try:
        return z.read(info)
    except zipfile.BadZipFile as e:
        # LSPatch deliberately aliases the original APK inside its ZIP.
        # Python 3.12 rejects this overlap; read the bounded stored entry,
        # validate its CRC and size, and never disable checks globally.
        if 'Overlapped entries' not in str(e) or info.filename != 'assets/lspatch/origin.apk':
            raise
        if info.compress_type != zipfile.ZIP_STORED or info.file_size > 512 * 1024 * 1024:
            raise ValueError('不支持的 LSPatch origin ZIP 布局')
        z.fp.seek(info.header_offset)
        header = z.fp.read(30)
        if header[:4] != b'PK\x03\x04':
            raise ValueError('origin ZIP local header 无效')
        n, e = struct.unpack_from('<HH', header, 26)
        z.fp.seek(n + e, 1)
        data = z.fp.read(info.file_size)
        if len(data) != info.file_size or zlib.crc32(data) & 0xffffffff != info.CRC:
            raise ValueError('origin APK 长度或 CRC 不一致')
        return data


def asset_hashes(path):
    with zipfile.ZipFile(path) as z:
        return {n: hashlib.sha256(zip_bytes(z, n)).hexdigest()
                for n in z.namelist() if n.startswith('assets/lspatch/') and not n.endswith('/')}


def main():
    parser = argparse.ArgumentParser(description='车来了 ARM64：内嵌 Xposed 模块 + Gadget flag 修复')
    parser.add_argument('--original', type=Path)
    parser.add_argument('--module', type=Path)
    parser.add_argument('--sigbypass', choices=['0', '1', '2', '3'], default='2')
    args = parser.parse_args()
    if sys.version_info < (3, 12):
        raise RuntimeError('需要 Python 3.12+（Ubuntu 24.04 默认满足）')
    original, module = choose_inputs(args)
    say('原包：' + str(original))
    say('模块：' + str(module))
    TOOLS.mkdir(exist_ok=True)
    java = get_java()
    say('Java：' + str(java))
    for name, url in URLS.items():
        fetch(url, TOOLS / name)
    gadget = TOOLS / 'gadget.so'
    if not gadget.is_file():
        temporary_gadget = gadget.with_suffix('.so.part')
        with lzma.open(TOOLS / 'gadget.so.xz') as src, temporary_gadget.open('wb') as dst:
            shutil.copyfileobj(src, dst)
        temporary_gadget.replace(gadget)
    with gadget.open('rb') as f:
        elf = f.read(20)
    if elf[:5] != b'\x7fELF\x02' or struct.unpack_from('<H', elf, 18)[0] != 183:
        raise ValueError('Gadget 不是 ARM64 ELF')
    job = ROOT / 'work' / time.strftime('%Y%m%d_%H%M%S')
    job.mkdir(parents=True, exist_ok=False)
    log = job / 'build.log'
    jar = lambda name: [java, '-Xmx2g', '-jar', TOOLS / name]
    say('[1/5] LSPatch 内嵌模块（保持未修改原包作为 origin）')
    patched = job / 'lspatch'
    run(jar('lspatch.jar') + [original, '-m', module, '-o', patched,
                             '--sigbypasslv', args.sigbypass, '--extract-libs', '-f'], log)
    candidates = list(patched.glob('*.apk'))
    if len(candidates) != 1:
        raise RuntimeError('LSPatch 输出 APK 数量异常')
    lsp_apk = candidates[0]
    assets_before = asset_hashes(lsp_apk)
    if sha(original) not in assets_before.values() or sha(module) not in assets_before.values():
        raise RuntimeError('未找到与输入一致的内嵌原包/模块，停止处理')
    say('[2/5] 解码 LSPatch 外层并注入早期 Gadget 加载')
    decoded = job / 'decoded'
    run(jar('apktool.jar') + ['d', '-f', '-r',
                             '--only-main-classes', '-o', decoded, lsp_apk], log)
    factory = inject(decoded)
    say('入口：' + factory + '.<clinit>')
    say('[3/5] 重建 APK；只保留 ARM64 原生库')
    unsigned = job / 'rebuilt.apk'
    run(jar('apktool.jar') + ['b', '-f', decoded, '-o', unsigned], log)
    say('[4/5] ZIP 对齐、生成/复用本地签名密钥')
    aligned = job / 'aligned.apk'
    align_apk(unsigned, aligned)
    if assets_before != asset_hashes(aligned):
        raise RuntimeError('内嵌原包或模块发生变化，停止签名')
    keystore = ROOT / 'signing.p12'
    if not keystore.exists():
        keytool = java.parent / 'keytool'
        if not keytool.is_file():
            found = shutil.which('keytool')
            if not found:
                raise RuntimeError('缺少 keytool，请安装 JDK 21 或 openjdk-17-jdk-headless')
            keytool = Path(found)
        run([keytool, '-genkeypair', '-noprompt', '-storetype', 'PKCS12',
             '-keystore', keystore, '-storepass', 'cll-local-build',
             '-keypass', 'cll-local-build', '-alias', 'cll', '-keyalg', 'RSA',
             '-keysize', '2048', '-validity', '10000',
             '-dname', 'CN=CLL Local Build,O=Local,C=CN'], log)
        keystore.chmod(0o600)
    say('[5/5] APK 签名和签名验证')
    signed_dir = job / 'signed'
    run(jar('uber-apk-signer.jar') + ['-a', aligned, '-o', signed_dir,
        '--skipZipAlign', '--ks', keystore, '--ksAlias', 'cll',
        '--ksPass', 'cll-local-build', '--ksKeyPass', 'cll-local-build'], log)
    signed = list(signed_dir.glob('*.apk'))
    if len(signed) != 1:
        raise RuntimeError('签名输出异常')
    run(jar('uber-apk-signer.jar') + ['-a', signed[0], '--onlyVerify', '--skipZipAlign'], log)
    check_alignment(signed[0])
    if assets_before != asset_hashes(signed[0]):
        raise RuntimeError('最终 APK 的 origin/module 检查失败')
    with zipfile.ZipFile(signed[0]) as z:
        for name in ('libcllflag.so', 'libcllflag.config.so', 'libcllflag.script.so'):
            if 'lib/arm64-v8a/' + name not in z.namelist():
                raise RuntimeError('最终 APK 缺少：' + name)
        if 'assets/lspatch/so/arm64-v8a/liblspatch.so' not in z.namelist():
            raise RuntimeError('最终 APK 缺少 LSPatch ARM64 loader')
    out = ROOT / 'out'
    out.mkdir(exist_ok=True)
    final = out / ('chelaile-module-flag-' + job.name + '.apk')
    shutil.copy2(signed[0], final)
    manifest = {'original_sha256': sha(original), 'module_sha256': sha(module),
                'result_sha256': sha(final), 'factory': factory,
                'frida': '17.15.5', 'sigbypass': args.sigbypass,
                'tools_sha256': {name: sha(TOOLS / name) for name in URLS}}
    (job / 'build-info.json').write_text(json.dumps(manifest, indent=2))
    say('\n打包成功：' + str(final))
    say('日志：' + str(log))
    say('安装后检查：adb logcat -s CLL.Flag')
    say('预期：ready ...，随后 flag=... 0 -> 64。未出现 flag 修改不代表修复成功。')


if __name__ == '__main__':
    try:
        main()
    except (Exception, KeyboardInterrupt) as e:
        print('\n打包失败：' + str(e), file=sys.stderr)
        sys.exit(1)
