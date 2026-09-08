# gen_shellcode.py -- extract .text$mn machine code from COFF obj -> C# byte[]
# Usage: python gen_shellcode.py [ManualMap_x64] [ManualMap_x86] [UnmapDll_x64] [UnmapDll_x86]
#   (defaults to all four; args are obj basenames without .obj)
import struct, sys

def extract_text(path):
    with open(path, 'rb') as f:
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

def fmt(blob):
    lines = []
    for i in range(0, len(blob), 12):
        chunk = blob[i:i+12]
        lines.append('        ' + ', '.join('0x%02X' % b for b in chunk) + ',')
    return '\n'.join(lines)

jobs = [
    ('ManualMap_x64.obj', 'ManualMapX64', 'shellcode_x64.cs'),
    ('ManualMap_x86.obj', 'ManualMapX86', 'shellcode_x86.cs'),
    ('UnmapDll_x64.obj',  'UnmapDllX64',  'unmap_x64.cs'),
    ('UnmapDll_x86.obj',  'UnmapDllX86',  'unmap_x86.cs'),
]

names = sys.argv[1:] or [j[0][:-4] for j in jobs]
out = []
for obj, cname, csfile in jobs:
    if obj[:-4] not in names:
        continue
    blob = extract_text(obj)
    out.append((cname, blob))
    with open(csfile, 'w', encoding='utf-8') as f:
        f.write('        public static readonly byte[] %s =\n        {\n%s\n        };\n' % (cname, fmt(blob)))
    print('%s -> %s (%d bytes)' % (obj, csfile, len(blob)))

# print a one-line size summary for the caller
print('SUMMARY: ' + ', '.join('%s=%d' % (n, len(b)) for n, b in out))
