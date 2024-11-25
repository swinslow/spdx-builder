# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024 Steve Winslow

# Based slightly on zspdx/writer.py from Zephyr Project:
# Copyright (c) 2021 The Linux Foundation

from datetime import datetime
import json
import os

from __init__ import VERSION

# Create and return dict for SPDX File JSON data.
# arguments:
# 1) f: File (defined in datatypes.py)
def makeSPDXJSONFile(f):
    fj = {}
    fj["SPDXID"] = f.spdxID
    fj["fileName"] = f.relpath
    fj["licenseConcluded"] = f.concludedLicense
    fj["licenseInfoInFiles"] = f.licenseInfoInFile
    fj["copyrightText"] = f.copyrightText
    fj["checksums"] = [{"algorithm": "SHA1", "checksumValue": f.sha1}]
    if f.sha256:
        fj["checksums"].append({"algorithm": "SHA256", "checksumValue": f.sha256})
    return fj

# Create and return dict for SPDX Package JSON data.
# Will also create File JSON dict objects for all Files contained
# in this Package, add them to the "files" list, and add them to
# the "hasFiles" list for this Package.
# Arguments:
# 1) p: Package (as defined in datatypes.py)
# 2) docFiles: list of all files in this _Document_
def makeSPDXJSONPackage(p, docFiles):
    pj = {}

    # get data from PackageConfig
    pj["SPDXID"] = p.cfg.spdxID
    pj["name"] = p.cfg.name
    if p.cfg.version:
        pj["versionInfo"] = p.cfg.version
    if p.cfg.supplierOrg:
        pj["supplier"] = f"Organization: {p.cfg.supplierOrg}"
    elif p.cfg.supplierPerson:
        pj["supplier"] = f"Person: {p.cfg.supplierPerson}"
    pj["licenseDeclared"] = p.cfg.declaredLicense
    pj["copyrightText"] = p.cfg.copyrightText
    # FIXME move downloadLocation into PackageConfig?
    pj["downloadLocation"] = "NOASSERTION"

    # get remaining data from Package
    pj["licenseConcluded"] = p.concludedLicense
    pj["licenseInfoFromFiles"] = p.licenseInfoFromFiles
    pj["filesAnalyzed"] = True
    pj["packageVerificationCode"] = {
        #"packageVerificationCodeExcludedFiles": [],
        "packageVerificationCodeValue": p.verificationCode,
    }

    pj["hasFiles"] = []
    for fID, f in p.files.items():
        fj = makeSPDXJSONFile(f)
        # FIXME might check whether a File with this ID is already in docFiles
        docFiles.append(fj)
        pj["hasFiles"].append(fID)

    return pj

# Create and return array for SPDX "Other Licensing Info"
# sections based on "LicenseRef-" license IDs in SPDX Document,
# or empty list if none.
def makeSPDXJSONOtherLicensingInfo(doc):
    # FIXME for now, just create placeholder extractedText for each
    licenseRefs = set()

    # FIXME should also handle DocumentRef-...:LicenseRef-... format
    for pkg in doc.pkgs.values():
        # check package's own licenses
        # FIXME for declared license, should check components of expression
        if pkg.cfg.declaredLicense.startswith("LicenseRef-"):
            licenseRefs.add(pkg.cfg.declaredLicense)
        # check licenseInfoFromFiles => shouldn't need to check each
        # individual file
        for l in pkg.licenseInfoFromFiles:
            if l.startswith("LicenseRef-"):
                licenseRefs.add(l)

    lj = []
    for lr in sorted(licenseRefs):
        lj.append({
            "licenseId": lr,
            "comment": f"Corresponds to the license ID `{lr}` detected in an SPDX-License-Identifier: tag.",
            "extractedText": lr,
            "name": lr,
        })
    return lj

# Create and return dict for SPDX Document JSON data, with
# sources and builds packages, all corresponding files, and
# all related relationships and other metadata.
# Arguments:
# 1) doc: Document (defined in datatypes.py)
def makeSPDXJSONDocument(doc):
    dj = {}

    # set up main document data
    dj = {
        "spdxVersion": "SPDX-2.2",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": doc.cfg.name,
        "documentNamespace": doc.cfg.namespace,
        "documentDescribes": [],
        "packages": [],
        "files": [],
        "relationships": [],
    }

    # set up document creation info
    dc = {}
    dc["created"] = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    dc["creators"] = [f"Tool: spdx-builder-{VERSION}"]
    dj["creationInfo"] = dc

    # add a package section for each package
    for pkgID, pkg in doc.pkgs.items():
        dj["documentDescribes"].append(pkgID)
        pj = makeSPDXJSONPackage(pkg, dj["files"])
        dj["packages"].append(pj)

    # add each relationship
    for rln in doc.relationships:
        rj = {
            "spdxElementId": rln.refA,
            "relatedSpdxElement": rln.refB,
            "relationshipType": rln.rlnType,
        }
        dj["relationships"].append(rj)

    # add other license info section, if any
    lj = makeSPDXJSONOtherLicensingInfo(doc)
    if len(lj) > 0:
        dj["hasExtractedLicensingInfos"] = lj

    return dj

# create and output SPDX JSON Document
# Arguments:
# 1) outputDir: folder to output SPDX JSON
# 2) doc: Document (defined in datatypes.py)
# 3) pretty: bool for whether to pretty-print JSON output
def writeSPDX(outputDir, doc, pretty):
    dj = makeSPDXJSONDocument(doc)

    # FIXME for single document output, maybe allow specifying full path
    spdxFilename = os.path.join(outputDir, "doc.spdx.json")
    with open(spdxFilename, "w") as f:
        if pretty:
            ds = json.dump(dj, f, indent=2)
        else:
            ds = json.dump(dj, f)
        print(f"Wrote SPDX JSON document to {spdxFilename}")
    # FIXME handle exceptions, e.g. OSError
