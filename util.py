# SPDX-License-Identifier: Apache-2.0

# Based on zspdx/util.py from Zephyr Project:
# Copyright (c) 2020, 2021 The Linux Foundation

import hashlib

def getHashes(filePath):
    """
    Scan for and return hashes.

    Arguments:
        - filePath: path to file to scan.
    Returns: tuple of (SHA1, SHA256) hashes for filePath, or
             None if file is not found.
    """
    hSHA1 = hashlib.sha1()
    hSHA256 = hashlib.sha256()

    try:
        with open(filePath, 'rb') as f:
            buf = f.read()
            hSHA1.update(buf)
            hSHA256.update(buf)
    except OSError:
        return None

    return (hSHA1.hexdigest(), hSHA256.hexdigest())
