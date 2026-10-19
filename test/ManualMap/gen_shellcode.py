# gen_shellcode.py -- extract .text$mn machine code from COFF obj -> C# byte[]
#
# Usage:
#   python gen_shellcode.py                 # regenerate all four .cs files
#   python gen_shellcode.py ManualMap_x64   # selected obj basenames (no .obj)
#   python gen_shellcode.py --apply         # also patch DllInjector\Program.cs in place
#   python gen_shellcode.py --check         # compare only; exit 1 if Program.cs is stale
#
# Why --apply / --check exist:
#   The four byte arrays in DllInjector\Program.cs are a *copy* of the assembled
#   .text section. Before this, keeping them in sync meant a human copy-pasting
#   the generated output -- an easy step to forget, and a stale array is
#   completely silent at build time (the injector just runs old shellcode).
#   --check is what CI runs: if someone edits an .asm and forgets to regenerate,
#   the build fails instead of shipping mismatched shellcode.
import os, re, struct, sys

HERE = os.path.dirname(os.path.abspath(__file__))
PROGRAM_CS = os.path.normpath(os.path.join(HERE, '..', '..', 'DllInjector', 'Program.cs'))

# Default indentation for the generated .cs snippets. When patching Program.cs
# the indent actually used is the one already on the declaration line, so a
# regeneration never re-indents the file (see find_array()).
INDENT = '        '

def extract_text(path):
    with open(os.path.join(HERE, path), 'rb') as f:
        data = f.read()
    num_sections = struct.unpack_from('<H', data, 2)[0]
    opt_size = struct.unpack_from('<H', data, 16)[0]
    sec_off = 20 + opt_size
    for i in range(num_sections):
        off = sec_off + i * 40
        name = data[off:off+8].rstrip(b'\0').decode()
        _, _, rawsize, rawptr = struct.unpack_from('<IIII', data, off + 8)
        if name.startswith('.text'):
            blob = data[rawptr:rawptr+rawsize]
            while len(blob) > 0 and blob[-1] == 0:
                blob = blob[:-1]
            return blob
    raise SystemExit('no .text section in ' + path)

def fmt(blob, indent=INDENT):
    lines = []
    for i in range(0, len(blob), 12):
        chunk = blob[i:i+12]
        lines.append(indent + ', '.join('0x%02X' % b for b in chunk) + ',')
    return '\n'.join(lines)

def array_literal(cname, blob, indent=INDENT):
    return ('%spublic static readonly byte[] %s =\n%s{\n%s\n%s};'
            % (indent, cname, indent, fmt(blob, indent), indent))

def find_array(text, cname):
    """Return (start, end, indent) of the whole array declaration.

    start includes the leading whitespace of the declaration line. That matters
    for --apply: the replacement text carries its own indent, so if the match
    started at "public" the old indent would survive and 8 more spaces would be
    prepended on every run -- each regeneration would re-indent the array and
    dirty Program.cs, which is exactly what CI's `git diff --exit-code`
    check trips over.
    """
    m = re.search(r'(?m)^([ \t]*)public static readonly byte\[\]\s+' + re.escape(cname)
                  + r'\s*=\s*\{.*?\};', text, re.S)
    if not m:
        raise SystemExit('array %s not found in Program.cs' % cname)
    return m.start(), m.end(), m.group(1)

def bytes_in_array(text, cname):
    s, e, _ = find_array(text, cname)
    body = text[s:e]
    return [int(v, 16) for v in re.findall(r'0x([0-9A-Fa-f]{2})', body)]

jobs = [
    ('ManualMap_x64.obj', 'ManualMapX64', 'shellcode_x64.cs'),
    ('ManualMap_x86.obj', 'ManualMapX86', 'shellcode_x86.cs'),
    ('UnmapDll_x64.obj',  'UnmapDllX64',  'unmap_x64.cs'),
    ('UnmapDll_x86.obj',  'UnmapDllX86',  'unmap_x86.cs'),
]

args = sys.argv[1:]
apply_mode = '--apply' in args
check_mode = '--check' in args
names = [a for a in args if not a.startswith('--')] or [j[0][:-4] for j in jobs]

def read_cs(path):
    """Read Program.cs preserving whether it started with a UTF-8 BOM.

    The source file ships with a BOM (it contains Chinese comments and is
    opened by tooling that honours the BOM). Rewriting it without the BOM
    would show up as a spurious one-line diff on every regeneration.
    """
    with open(path, 'rb') as f:
        raw = f.read()
    has_bom = raw.startswith(b'\xef\xbb\xbf')
    if has_bom:
        raw = raw[3:]
    return raw.decode('utf-8'), has_bom

def write_cs(path, text, has_bom):
    data = text.encode('utf-8')
    if has_bom:
        data = b'\xef\xbb\xbf' + data
    with open(path, 'wb') as f:
        f.write(data)

# ---- --check: compare assembled .obj bytes against what Program.cs already has
if check_mode:
    if not os.path.exists(PROGRAM_CS):
        raise SystemExit('Program.cs not found: ' + PROGRAM_CS)
    cs, _ = read_cs(PROGRAM_CS)
    stale = []
    for obj, cname, _ in jobs:
        if obj[:-4] not in names:
            continue
        want = list(extract_text(obj))
        have = bytes_in_array(cs, cname)
        if want != have:
            stale.append('%s: obj=%d bytes, Program.cs=%d bytes%s'
                         % (cname, len(want), len(have),
                            '' if len(want) != len(have) else ' (same length, different content)'))
    if stale:
        print('SHELLCODE_STALE')
        for line in stale:
            print('  ' + line)
        print('Fix: run build_shellcode.bat (it now patches Program.cs directly).')
        raise SystemExit(1)
    print('SHELLCODE_OK: Program.cs arrays match the assembled .obj files')
    raise SystemExit(0)

out = []
for obj, cname, csfile in jobs:
    if obj[:-4] not in names:
        continue
    blob = extract_text(obj)
    out.append((cname, blob))
    with open(os.path.join(HERE, csfile), 'w', encoding='utf-8', newline='\n') as f:
        f.write(array_literal(cname, blob) + '\n')
    print('%s -> %s (%d bytes)' % (obj, csfile, len(blob)))

# ---- --apply: patch the arrays straight into Program.cs
if apply_mode:
    cs, has_bom = read_cs(PROGRAM_CS)
    for cname, blob in out:
        s, e, indent = find_array(cs, cname)
        cs = cs[:s] + array_literal(cname, blob, indent) + cs[e:]
    write_cs(PROGRAM_CS, cs, has_bom)
    print('APPLIED: patched %d array(s) into %s' % (len(out), PROGRAM_CS))

# print a one-line size summary for the caller
print('SUMMARY: ' + ', '.join('%s=%d' % (n, len(b)) for n, b in out))
