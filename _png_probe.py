import struct, zlib #struct allows binary data interpretation and converts bytes to data types  # executes the statement
from pathlib import Path #pathlib allows the application to work with local file on the computer   # imports Path #pathlib allows the application to work with local file on the computer from the pathlib module
for name in ("Branding White.png", "Branding.png"): #loop -- variable name and two user-provided images   # loops over the collection
    p = Path(name).read_bytes() # read each of the images and read the contents as binary data   # creates the path object
    assert p[:8] == b"\x89PNG\r\n\x1a\n"  # verifies the assumption
    pos = 8  # assigns the computed value to pos
    chunks = []  # assigns the computed value to chunks
    while pos + 8 <= len(p):  # loops while the condition holds
        length, ctype = struct.unpack(">I4s", p[pos:pos+8])  # runs the unpack() call
        chunks.append((ctype.decode("ascii", "replace"), length))  # adds an item to the list
        if ctype == b"IHDR":  # evaluates the branch condition
            w, h, depth, ctype2, comp, filt, interlace = struct.unpack(">IIBBBBB", p[pos+8:pos+8+13])  # runs the unpack() call
            print(name, "IHDR", w, h, "depth", depth, "colorType", ctype2, "interlace", interlace)  # runs the print() call
        if ctype == b"PLTE":  # evaluates the branch condition
            print(name, "has PLTE", length // 3, "colours")  # runs the print() call
        pos += 12 + length  # evaluates the pos expression
    print(name, "chunks:", chunks)  # runs the print() call
