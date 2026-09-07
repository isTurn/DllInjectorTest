# gen_shellcode.py -- extract .text$mn machine code from COFF obj -> C# byte[]
import struct

def extract_text(path):
    with open(path, 'rb') as f:
        data = f.read()
    # COFF object: no DOS/PE header, direct COFF format
    num_sections = struct.unpack_from('<H', data, 2)[0]
    opt_size = struct.unpack_from('<H', data, 16)[0]
    sec_off = 20 + opt_size
    for i in range(num_sections):
        off = sec_off + i * 40
        name = data[off:off+8].rstrip(b'\0').decode()
        _, _, rawsize, rawptr = struct.unpack_from('<IIII', data, off + 8)
        if name.startswith('.text'):
            blob = data[rawptr:rawptr+rawsize]
            # strip trailing zero padding (COFF aligns raw to 4)
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

x64 = extract_text('ManualMap_x64.obj')
x86 = extract_text('ManualMap_x86.obj')
print('x64 bytes:', len(x64))
print('x86 bytes:', len(x86))

with open('shellcode_x64.cs', 'w', encoding='utf-8') as f:
    f.write('        public static readonly byte[] ManualMapX64 =\n        {\n' + fmt(x64) + '\n        };\n')
with open('shellcode_x86.cs', 'w', encoding='utf-8') as f:
    f.write('        public static readonly byte[] ManualMapX86 =\n        {\n' + fmt(x86) + '\n        };\n')
print('written: shellcode_x64.cs / shellcode_x86.cs')
