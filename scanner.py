# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024 Steve Winslow

# Based on zspdx/scanner.py from Zephyr Project:
# Copyright (c) 2020, 2021 The Linux Foundation

import hashlib
import os
import re
import uuid

from datatypes import File, Package
from util import getHashes

# ScannerConfig contains settings used to configure the scanning for
# SPDX Document creation (e.g. license IDs, hashes, etc.)
class ScannerConfig:
    def __init__(self):
        super(ScannerConfig, self).__init__()

        # when assembling a Package's data, should we auto-conclude the
        # Package's license, based on the licenses of its Files?
        self.shouldConcludePackageLicense = True

        # when assembling a Package's Files' data, should we auto-conclude
        # each File's license, based on its detected license(s)?
        self.shouldConcludeFileLicenses = True

        # number of lines from the top of each file to scan for
        # SPDX-License-Identifier tag (0 = all)
        self.numLinesScanned = 20

        # SHA1 hashes are mandatory, per SPDX 2.2
        # should we also calculate SHA256 hashes for each File?
        self.doSHA256 = True

def scanPackage(scanCfg, pkgCfg):
    """
    Scan for licenses and calculate hashes for all files specified in
    pkgCfg.fileListPath, builds the Files and Package, and returns the
    Package.

    Arguments:
        - scanCfg: ScannerConfig
        - pkgCfg: PackageConfig
    """

    # get list of files to include in Package
    try:
        filesToScan = []
        with open(pkgCfg.fileListPath, "r") as flist:
            lines = flist.readlines()
            for l in lines:
                filesToScan.append(l.rstrip())
    except OSError as e:
        print(f"Error loading {pkgCfg.fileListPath}: {str(e)}")
        return None

    # prepare Package metadata
    pkg = Package(pkgCfg)

    # walk through and create each File object, scan it, and add to the package
    for fileRelPath in filesToScan:
        f = File(pkg)
        f.relpath = fileRelPath
        f.abspath = os.path.normpath(os.path.join(os.path.abspath(pkg.cfg.basedir), fileRelPath))
        f.spdxID = f"SPDXRef-File-{str(uuid.uuid4())}"
        pkg.files[f.spdxID] = f

        # get hashes for file
        hashes = getHashes(f.abspath)
        if not hashes:
            continue
        hSHA1, hSHA256 = hashes
        f.sha1 = hSHA1
        if scanCfg.doSHA256:
            f.sha256 = hSHA256

        # get licenses for file
        expression = getExpressionData(f.abspath, scanCfg.numLinesScanned)
        if expression:
            if scanCfg.shouldConcludeFileLicenses:
                f.concludedLicense = expression
            f.licenseInfoInFile = splitExpression(expression)

    # now, assemble the Package data
    licsConcluded, licsFromFiles = getPackageLicenses(pkg)
    if scanCfg.shouldConcludePackageLicense:
        pkg.concludedLicense = normalizeExpression(licsConcluded)
    pkg.licenseInfoFromFiles = licsFromFiles
    pkg.verificationCode = calculateVerificationCode(pkg)

    return pkg

def parseLineForExpression(line):
    """Return parsed SPDX expression if tag found in line, or None otherwise."""
    p = line.partition("SPDX-License-Identifier:")
    if p[2] == "":
        return None
    # strip away trailing comment marks and whitespace, if any
    expression = p[2].strip()
    expression = expression.rstrip("/*")
    expression = expression.strip()
    return expression

def getExpressionData(filePath, numLines):
    """
    Scans the specified file for the first SPDX-License-Identifier:
    tag in the file.

    Arguments:
        - filePath: pathto file to scan.
        - numLines: number of lines to scan for an expression before
                    giving up. If 0, will scan the entire file.
    Returns: parsed expression if found; None if not found.
    """
    with open(filePath, "r") as f:
        try:
            lineno = 0
            for line in f:
                lineno += 1
                if lineno > numLines > 0:
                    break
                expression = parseLineForExpression(line)
                if expression is not None:
                    return expression
        except UnicodeDecodeError:
            # invalid UTF-8 content
            return None

    # if we get here, we didn't find an expression
    return None

def splitExpression(expression):
    """
    Parse a license expression into its constituent identifiers.

    Arguments:
        - expression: SPDX license expression
    Returns: array of split identifiers
    """
    # remove parens and plus sign
    e2 = re.sub(r'\(|\)|\+', "", expression, flags=re.IGNORECASE)

    # remove word operators, ignoring case, leaving a blank space
    e3 = re.sub(r' AND | OR | WITH ', " ", e2, flags=re.IGNORECASE)

    # and split on space
    e4 = e3.split(" ")

    return sorted(e4)

def calculateVerificationCode(pkg):
    """
    Calculate the SPDX Package Verification Code for all files in the package.

    Arguments:
        - pkg: Package
    Returns: verification code as string
    """
    hashes = []
    for f in pkg.files.values():
        hashes.append(f.sha1)
    hashes.sort()
    filelist = "".join(hashes)

    hSHA1 = hashlib.sha1()
    hSHA1.update(filelist.encode('utf-8'))
    return hSHA1.hexdigest()

def getPackageLicenses(pkg):
    """
    Extract lists of all concluded and infoInFile licenses seen.

    Arguments:
        - pkg: Package
    Returns: sorted list of concluded license exprs,
             sorted list of infoInFile ID's
    """
    licsConcluded = set()
    licsFromFiles = set()
    for f in pkg.files.values():
        licsConcluded.add(f.concludedLicense)
        for licInfo in f.licenseInfoInFile:
            licsFromFiles.add(licInfo)
    return sorted(list(licsConcluded)), sorted(list(licsFromFiles))

def normalizeExpression(licsConcluded):
    """
    Combine array of license expressions into one AND'd expression,
    adding parens where needed.

    Arguments:
        - licsConcluded: array of license expressions
    Returns: string with single AND'd expression.
    """
    # return appropriate for simple cases
    if len(licsConcluded) == 0:
        return "NOASSERTION"
    if len(licsConcluded) == 1:
        return licsConcluded[0]

    # more than one, so we'll need to combine them
    # iff an expression has spaces, it needs parens
    revised = []
    for lic in licsConcluded:
        if lic in ["NONE", "NOASSERTION"]:
            continue
        if " " in lic:
            revised.append(f"({lic})")
        else:
            revised.append(lic)
    return " AND ".join(revised)
