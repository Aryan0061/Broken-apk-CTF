import struct, hashlib, zlib, sys

def uleb128(n):
    out = bytearray()
    while True:
        b = n & 0x7f
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)

def mutf8_string_data(s):
    # ASCII-only strings in this challenge, so MUTF-8 == UTF-8
    b = s.encode('utf-8')
    return uleb128(len(s)) + b + b'\x00'

# ---- string pool (sorted by code point per DEX spec) ----
strings = [
    "B",
    "Lcom/cybercorrupt/flagvault/FlagVault;",
    "Ljava/lang/Object;",
    "Ljava/lang/String;",
    "PART1_B64",
    "PART2_ENC",
    "XOR_KEY",
    "[B",
    "aW5yb29tY3Rme2QzeF9oM2FkM3Jf",
]
strings_sorted = sorted(strings)
assert strings_sorted == strings, strings_sorted
str_idx = {s: i for i, s in enumerate(strings)}

# ---- type ids (sorted by descriptor string id) ----
type_descriptors = ["B", "Lcom/cybercorrupt/flagvault/FlagVault;", "Ljava/lang/Object;",
                     "Ljava/lang/String;", "[B"]
type_idx = {}
for i, t in enumerate(type_descriptors):
    type_idx[t] = i

TYPE_B = type_idx["B"]
TYPE_FLAGVAULT = type_idx["Lcom/cybercorrupt/flagvault/FlagVault;"]
TYPE_OBJECT = type_idx["Ljava/lang/Object;"]
TYPE_STRING = type_idx["Ljava/lang/String;"]
TYPE_BARR = type_idx["[B"]

# ---- field ids (sorted by class, then name, then type) ----
fields = [
    ("PART1_B64", TYPE_STRING),
    ("PART2_ENC", TYPE_BARR),
    ("XOR_KEY",   TYPE_B),
]
# already sorted by name string idx ascending (4,5,6)


# NOTE: corrected byte array. The originally supplied 14-byte array cannot
# decode to a 25-character string ("f1x3d_4nd_4pk_d3c0mp1l3d}") under any
# single-byte XOR key, since XOR is a 1:1 byte mapping (length must match).
# Recomputed here as XOR(ord(c), 0x5A) for each character of the real
# flag part 2, so the puzzle is internally consistent.
xor_bytes = [0x3c, 0x6b, 0x22, 0x69, 0x3e, 0x05, 0x6e, 0x34, 0x3e, 0x05, 0x6e, 0x2a,
             0x31, 0x05, 0x3e, 0x69, 0x39, 0x6a, 0x37, 0x2a, 0x6b, 0x36, 0x69, 0x3e, 0x27]

# sanity check the puzzle actually decodes
key = 0x5A
part2 = ''.join(chr(b ^ key) for b in xor_bytes)
print("part2 decoded:", part2)
import base64
part1 = base64.b64decode("aW5yb29tY3Rme2QzeF9oM2FkM3Jf").decode()
print("part1 decoded:", part1)
print("FULL FLAG:", part1 + part2)

# ============ Layout ============
HEADER_SIZE = 0x70

# --- string_ids table (4 bytes each: uint string_data_off), placeholder offsets patched later
n_strings = len(strings)
string_ids_off = HEADER_SIZE
string_ids_size_bytes = n_strings * 4

# --- type_ids table (4 bytes each)
type_ids_off = string_ids_off + string_ids_size_bytes
n_types = len(type_descriptors)
type_ids_size_bytes = n_types * 4

# --- proto_ids: none
proto_ids_off = 0
n_protos = 0

# --- field_ids table (8 bytes each: ushort class_idx, ushort type_idx, uint name_idx)
field_ids_off = type_ids_off + type_ids_size_bytes
n_fields = len(fields)
field_ids_size_bytes = n_fields * 8

# --- method_ids: none
method_ids_off = 0
n_methods = 0

# --- class_defs table (32 bytes each)
class_defs_off = field_ids_off + field_ids_size_bytes
n_classdefs = 1
class_defs_size_bytes = n_classdefs * 32

data_start = class_defs_off + class_defs_size_bytes
assert data_start % 4 == 0, data_start

# ---- build data section ----
data = bytearray()
string_data_offsets = []
for s in strings:
    string_data_offsets.append(data_start + len(data))
    data += mutf8_string_data(s)

# class_data_item
class_data_off = data_start + len(data)
cd = bytearray()
cd += uleb128(3)  # static_fields_size
cd += uleb128(0)  # instance_fields_size
cd += uleb128(0)  # direct_methods_size
cd += uleb128(0)  # virtual_methods_size
prev = 0
field_name_to_idx = {name: i for i, (name, t) in enumerate(fields)}
for name, t in fields:
    fidx = field_name_to_idx[name]
    diff = fidx - prev
    prev = fidx
    cd += uleb128(diff)
    cd += uleb128(0x19)  # public static final
data += cd

# encoded_array_item (static values), order matches static_fields order: PART1_B64, PART2_ENC, XOR_KEY
static_values_off = data_start + len(data)
ev = bytearray()
ev += uleb128(3)  # size = number of values
# VALUE_STRING for PART1_B64
s_idx = str_idx["aW5yb29tY3Rme2QzeF9oM2FkM3Jf"]
assert s_idx < 256
ev += bytes([0x17])  # value_arg=0 (1 byte), type=STRING(0x17)
ev += bytes([s_idx])
# VALUE_ARRAY for PART2_ENC
ev += bytes([0x1c])  # VALUE_ARRAY, no value_arg
ev += uleb128(len(xor_bytes))
for b in xor_bytes:
    ev += bytes([0x00])  # VALUE_BYTE, 1 byte
    ev += bytes([b & 0xff])
# VALUE_BYTE for XOR_KEY
ev += bytes([0x00])
ev += bytes([key & 0xff])
data += ev

# ---- map_list (4-byte aligned) ----
pad = (-len(data)) % 4
data += b'\x00' * pad
map_list_off = data_start + len(data)

TYPE_HEADER_ITEM = 0x0000
TYPE_STRING_ID_ITEM = 0x0001
TYPE_TYPE_ID_ITEM = 0x0002
TYPE_FIELD_ID_ITEM = 0x0004
TYPE_CLASS_DEF_ITEM = 0x0006
TYPE_MAP_LIST = 0x1000
TYPE_STRING_DATA_ITEM = 0x2002
TYPE_CLASS_DATA_ITEM = 0x2000
TYPE_ENCODED_ARRAY_ITEM = 0x2005

map_entries = [
    (TYPE_HEADER_ITEM, 1, 0),
    (TYPE_STRING_ID_ITEM, n_strings, string_ids_off),
    (TYPE_TYPE_ID_ITEM, n_types, type_ids_off),
    (TYPE_FIELD_ID_ITEM, n_fields, field_ids_off),
    (TYPE_CLASS_DEF_ITEM, n_classdefs, class_defs_off),
    (TYPE_STRING_DATA_ITEM, n_strings, string_data_offsets[0]),
    (TYPE_CLASS_DATA_ITEM, 1, class_data_off),
    (TYPE_ENCODED_ARRAY_ITEM, 1, static_values_off),
    (TYPE_MAP_LIST, 1, map_list_off),
]
map_entries.sort(key=lambda e: e[2])

ml = bytearray()
ml += struct.pack('<I', len(map_entries))
for t, size, off in map_entries:
    ml += struct.pack('<HHII', t, 0, size, off)
data += ml

file_size = data_start + len(data)
data_size = len(data)
data_off = data_start

# ============ build fixed-size tables ============
string_ids_bytes = b''.join(struct.pack('<I', off) for off in string_data_offsets)

type_ids_bytes = b''.join(struct.pack('<I', str_idx[t]) for t in type_descriptors)

field_ids_bytes = bytearray()
for name, t in fields:
    field_ids_bytes += struct.pack('<HHI', TYPE_FLAGVAULT, t, str_idx[name])

NO_INDEX = 0xFFFFFFFF
class_def_bytes = struct.pack('<IIIIIIII',
    TYPE_FLAGVAULT,   # class_idx
    0x1,              # access_flags: public
    TYPE_OBJECT,      # superclass_idx
    0,                # interfaces_off
    NO_INDEX,         # source_file_idx
    0,                # annotations_off
    class_data_off,   # class_data_off
    static_values_off # static_values_off
)

# ============ header (with placeholder checksum/signature) ============
def build_header(checksum, signature):
    return struct.pack('<8sI20sIIIIIIIIIIIIIIIIII',
        b'dex\n035\x00',
        checksum,
        signature,
        file_size,
        HEADER_SIZE,
        0x12345678,          # endian_tag
        0, 0,                # link_size, link_off
        map_list_off,        # map_off
        n_strings, string_ids_off,
        n_types, type_ids_off,
        n_protos, proto_ids_off,
        n_fields, field_ids_off,
        n_methods, method_ids_off,
        n_classdefs, class_defs_off,
    ) + struct.pack('<II', data_size, data_off)

header_stub = build_header(0, b'\x00'*20)
assert len(header_stub) == HEADER_SIZE, len(header_stub)

body = string_ids_bytes + type_ids_bytes + field_ids_bytes + class_def_bytes + bytes(data)
assert HEADER_SIZE + len(body) == file_size

full = bytearray(header_stub + body)

# signature = SHA1 over everything after the 32-byte (magic+checksum+signature) header prefix
signature = hashlib.sha1(full[32:]).digest()
full[12:32] = signature

# checksum = adler32 over everything after the checksum field (offset 12 onward)
checksum = zlib.adler32(bytes(full[12:])) & 0xffffffff
full[8:12] = struct.pack('<I', checksum)

with open('classes_fixed.dex', 'wb') as f:
    f.write(full)

print("Wrote classes_fixed.dex,", len(full), "bytes")
print("magic:", full[0:8])
