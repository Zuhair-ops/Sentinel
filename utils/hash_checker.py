import hashlib


def calculate_hashes(file):

    sha256 = hashlib.sha256()
    sha512 = hashlib.sha512()
    md5 = hashlib.md5()

    total_size = 0

    while True:

        chunk = file.read(4096)

        if not chunk:
            break

        total_size += len(chunk)

        sha256.update(chunk)
        sha512.update(chunk)
        md5.update(chunk)

    return {
        "sha256": sha256.hexdigest(),
        "sha512": sha512.hexdigest(),
        "md5": md5.hexdigest(),
        "size": total_size
    }


def verify_hash(actual_hash, expected_hash):

    if not expected_hash:
        return None

    return actual_hash.strip().lower() == expected_hash.strip().lower()