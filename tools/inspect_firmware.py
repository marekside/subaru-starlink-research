"""Offline inspection only: never executes firmware or writes to the input tree.

IFS field layout reference:
https://github.com/askac/dumpifs/blob/master/sys/image.h
Standalone imagefs and little-endian ARM startup IFS with LZO1X blocks are
supported. Symlinks and devices are inventoried but never created. Checksums
here do not authenticate firmware. Startup decompression requires lzokay.
"""

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import struct


def separate_output(source, output):
    source, output = source.resolve(), output.resolve()
    if output == source or output.is_relative_to(source):
        raise ValueError("Output must be outside the source tree")
    return output


def hashes(path):
    sha256 = hashlib.sha256()
    md5 = hashlib.md5(usedforsecurity=False)
    with path.open("rb") as stream:
        while block := stream.read(4 * 1024 * 1024):
            sha256.update(block)
            md5.update(block)
    return sha256.hexdigest(), md5.hexdigest()


def inventory(source, output, hash_maps):
    output = separate_output(source, output)
    rows = []
    for path in sorted(source.rglob("*")):
        if path.is_symlink():
            raise ValueError(f"Input symlink not supported: {path}")
        if not path.is_file():
            continue
        relative = path.relative_to(source).as_posix()
        with path.open("rb") as stream:
            header = stream.read(96)
        row = {"path": relative, "bytes": path.stat().st_size,
               "header_hex": header.hex(), "sha256": None}
        if hash_maps or not relative.startswith("map/"):
            row["sha256"], md5 = hashes(path)
            if relative == "swdl.iso":
                expected = re.search(r"\b[0-9a-fA-F]{32}\b",
                                     (source / "swdl.iso.md5").read_text())
                row["md5"] = md5
                row["supplied_md5_matches"] = bool(
                    expected and expected[0].lower() == md5)
        else:
            row["hash_note"] = "Skipped map hash; use --hash-maps for full baseline"
        if header.startswith(b"QNXCNDFS"):
            row["format"] = "QNXCNDFS"
            row["flags_at_0x0c"] = struct.unpack_from("<I", header, 12)[0]
        rows.append(row)
        print(f"{relative}: {row['bytes']} bytes", flush=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8") as stream:
        json.dump({"source_name": source.name, "files": rows}, stream, indent=2)
        stream.write("\n")


def read_ifs(source):
    return read_imagefs(source.read_bytes())


def read_imagefs(data):
    if len(data) < 92:
        raise ValueError("Truncated imagefs header")
    if not data.startswith(b"imagefs"):
        raise ValueError("Expected standalone uncompressed imagefs; startup/compressed IFS unsupported")
    endian = ">" if data[7] & 1 else "<"
    image_size, directory_end, directory_start = struct.unpack_from(endian + "III", data, 8)
    if not 92 <= directory_start < directory_end <= image_size <= len(data):
        raise ValueError("Invalid imagefs bounds")
    if image_size % 4 or sum(x[0] for x in struct.iter_unpack(endian + "I", data[:image_size])) & 0xffffffff:
        raise ValueError("Imagefs additive checksum mismatch")
    entries = []
    cursor = directory_start
    while cursor + 2 <= directory_end:
        size = struct.unpack_from(endian + "H", data, cursor)[0]
        if size == 0:
            break
        if size < 24 or cursor + size > directory_end:
            raise ValueError("Invalid directory entry bounds")
        record = data[cursor:cursor + size]
        _, _, inode, mode, gid, uid, mtime = struct.unpack_from(endian + "HHIIIII", record)
        kind = stat.S_IFMT(mode)
        path_offset = 24 if kind == stat.S_IFDIR else 28 if kind == stat.S_IFLNK else 32
        if len(record) <= path_offset:
            raise ValueError("Truncated directory entry")
        raw_path, separator, _ = record[path_offset:].partition(b"\0")
        if not separator:
            raise ValueError("Unterminated path")
        name = raw_path.decode("utf-8", errors="strict")
        entry = {"path": name, "inode": inode, "mode": oct(mode),
                 "uid": uid, "gid": gid, "mtime": mtime, "type": "other"}
        if kind == stat.S_IFREG:
            offset, length = struct.unpack_from(endian + "II", record, 24)
            if offset < directory_end or offset + length > image_size:
                raise ValueError(f"File outside image payload: {name}")
            entry.update(type="file", offset=offset, bytes=length,
                         sha256=hashlib.sha256(data[offset:offset + length]).hexdigest())
        elif kind == stat.S_IFLNK:
            link_offset, link_size = struct.unpack_from(endian + "HH", record, 24)
            link_offset += 28  # Relative to the symlink path field.
            if link_offset + link_size > len(record):
                raise ValueError("Symlink outside directory record")
            entry.update(type="symlink", target=record[link_offset:link_offset + link_size].rstrip(b"\0").decode())
        elif kind == stat.S_IFDIR:
            entry["type"] = "directory"
        entries.append(entry)
        cursor += size
    return data, entries


def extract_ifs(source, output):
    output = separate_output(source.parent, output)
    data, entries = read_ifs(source)
    extract_entries(data, entries, output)


def extract_entries(data, entries, output):
    # A new directory prevents accidentally following existing links or replacing files.
    output.mkdir(parents=True, exist_ok=False)
    files_root = output / "files"
    files_root.mkdir()
    for entry in entries:
        if entry["type"] != "file":
            continue
        name = entry["path"]
        parts = PurePosixPath(name).parts
        if not name or name.startswith("/") or ".." in parts or "\\" in name or ":" in name:
            raise ValueError(f"Unsafe extraction path: {name!r}")
        target = files_root.joinpath(*parts)
        if not target.resolve().is_relative_to(files_root.resolve()):
            raise ValueError("Extraction escaped output")
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as stream:
            start = entry["offset"]
            stream.write(data[start:start + entry["bytes"]])
    (output / "manifest.json").write_text(json.dumps(entries, indent=2) + "\n", encoding="utf-8")
    print(f"Inventoried {len(entries)} entries; extracted regular files to {files_root}")


def startup_ifs(source, output):
    import lzokay

    output = separate_output(source.parent, output)
    data = source.read_bytes()
    if len(data) < 256 or data[:4] != b"\xeb\x7e\xff\0":
        raise ValueError("Expected ARM startup IFS at offset zero")
    if data[6] & 2 or data[6] & 0x1c != 8:
        raise ValueError("Only little-endian LZO startup IFS supported")
    start, stored, _, expected = struct.unpack_from("<IIII", data, 32)
    if not 256 <= start < stored <= len(data) or expected > 256 * 1024 * 1024:
        raise ValueError("Invalid startup IFS bounds")
    cursor = start
    chunks = []
    total = 0
    while cursor + 2 <= stored:
        size = int.from_bytes(data[cursor:cursor + 2], "big")
        cursor += 2
        if not size:
            break
        if cursor + size > stored:
            raise ValueError("Compressed block outside startup image")
        chunk = lzokay.decompress(data[cursor:cursor + size], 65536)
        cursor += size
        chunks.append(chunk)
        total += len(chunk)
        if total > ((expected + 65535) // 65536) * 65536:
            raise ValueError("Decompressed image exceeds declared size")
    else:
        raise ValueError("Missing compressed stream terminator")
    padded = b"".join(chunks)
    if len(padded) < expected or any(padded[expected:]) or expected % 4:
        raise ValueError("Decompressed image size mismatch")
    image = padded[:expected]
    checksum = sum(x[0] for x in struct.iter_unpack("<I", image)) & 0xffffffff
    if checksum:
        raise ValueError("Imagefs additive checksum mismatch")
    _, entries = read_imagefs(image)
    extract_entries(image, entries, output)
    (output / "imagefs.ifs").write_bytes(image)
    metadata = {"startup_bytes": start, "stored_bytes": stored,
                "imagefs_bytes": expected, "lzo_blocks": len(chunks),
                "zero_padding_bytes": len(padded) - expected,
                "imagefs_checksum_valid": True,
                "imagefs_sha256": hashlib.sha256(image).hexdigest()}
    (output / "startup.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(metadata))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    inv = commands.add_parser("inventory")
    inv.add_argument("source", type=Path)
    inv.add_argument("output", type=Path)
    inv.add_argument("--hash-maps", action="store_true")
    ifs = commands.add_parser("ifs")
    ifs.add_argument("source", type=Path)
    ifs.add_argument("output", type=Path)
    startup = commands.add_parser("startup-ifs")
    startup.add_argument("source", type=Path)
    startup.add_argument("output", type=Path)
    args = parser.parse_args()
    if args.command == "inventory":
        inventory(args.source, args.output, args.hash_maps)
    elif args.command == "ifs":
        extract_ifs(args.source, args.output)
    else:
        startup_ifs(args.source, args.output)


if __name__ == "__main__":
    main()
