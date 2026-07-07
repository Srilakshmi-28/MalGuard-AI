import os
import hashlib
import mimetypes
import math
from datetime import datetime


def calculate_entropy(filepath):

    with open(filepath, "rb") as f:
        data = f.read()

    if len(data) == 0:
        return 0

    entropy = 0

    for x in range(256):

        p_x = data.count(bytes([x])) / len(data)

        if p_x > 0:
            entropy -= p_x * math.log2(p_x)

    return round(entropy, 2)


def sha256_hash(filepath):

    sha = hashlib.sha256()

    with open(filepath, "rb") as f:

        while True:

            data = f.read(4096)

            if not data:
                break

            sha.update(data)

    return sha.hexdigest()


def analyze_file(filepath):

    filename = os.path.basename(filepath)

    filesize = round(os.path.getsize(filepath) / 1024, 2)

    extension = os.path.splitext(filename)[1]

    mime = mimetypes.guess_type(filepath)[0]

    entropy = calculate_entropy(filepath)

    sha = sha256_hash(filepath)

    scan_time = datetime.now().strftime("%d-%m-%Y %I:%M %p")

    return {

        "filename": filename,

        "filesize": filesize,

        "extension": extension,

        "filetype": mime,

        "entropy": entropy,

        "sha256": sha,

        "scan_time": scan_time

    }