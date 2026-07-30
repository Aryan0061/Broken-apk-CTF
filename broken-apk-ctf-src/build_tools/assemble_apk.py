import zipfile, shutil

FIXED_DEX = "classes_fixed.dex"
GOOD_MAGIC = b"dex\n"
BAD_MAGIC = b"bad\n"

with open(FIXED_DEX, "rb") as f:
    dex = bytearray(f.read())

assert dex[0:4] == GOOD_MAGIC, "expected valid dex magic before corrupting"

# Corrupt just the DEX magic header (first 4 bytes), leave version + rest intact
dex_broken = bytes(BAD_MAGIC) + bytes(dex[4:])

with open("classes_broken.dex", "wb") as f:
    f.write(dex_broken)

# Assemble the APK (unsigned zip archive — this is a static-analysis puzzle,
# it is never meant to be installed on a device)
with zipfile.ZipFile("broken_app.apk", "w", zipfile.ZIP_DEFLATED) as z:
    z.write("AndroidManifest.xml", "AndroidManifest.xml")
    z.write("strings.xml", "res/values/strings.xml")
    z.writestr("classes.dex", dex_broken)
    z.writestr(
        "META-INF/CHALLENGE.txt",
        "CyberCorrupt Mobile Repair Lab\n"
        "Diagnostic ticket #4471: classes.dex fails header verification.\n"
        "Repair the DEX magic before running static analysis tools.\n",
    )

print("wrote broken_app.apk")
with zipfile.ZipFile("broken_app.apk") as z:
    for n in z.namelist():
        print(" -", n, z.getinfo(n).file_size, "bytes")

with open("broken_app.apk", "rb") as f:
    apk_bytes = f.read()
import hashlib
print("apk sha256:", hashlib.sha256(apk_bytes).hexdigest())
print("apk size:", len(apk_bytes))
