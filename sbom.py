# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024 Steve Winslow

# Based on zspdx/sbom.py from Zephyr Project:
# Copyright (c) 2020, 2021 The Linux Foundation

import argparse
import os
import uuid

from datatypes import Document, DocumentConfig, PackageConfig, Relationship
from scanner import ScannerConfig, scanPackage
from writer import writeSPDX

# SBOMConfig contains settings that will be passed along to the various
# SBOM maker subcomponents.
class SBOMConfig:
    def __init__(self):
        super(SBOMConfig, self).__init__()

        # path to text file with list of source files to include
        # first positional argument
        self.sourceList = ""

        # root directory for source files
        # second positional argument
        self.srcdir = ""

        # path to text file with list of build files to include
        # third positional argument
        self.buildList = ""

        # root directory for build files
        # fourth positional argument
        self.builddir = ""

        # prefix for Document namespaces; should not end with "/"
        # argument: -n / --namespace-prefix
        self.namespacePrefix = ""

        # path to directory to write SPDX JSON files
        # argument: -o / --output
        self.outputDir = "."

        # name to use for package prefixes
        # argument: --package-name
        self.packageName = "mycode"

        # version number to use for packages
        # argument: --package-version
        self.packageVersion = ""

        # declared license for packages
        # argument: --package-license
        self.packageDeclaredLicense = "NOASSERTION"

        # supplier -- can only specify one, either Person or Organization
        # argument: --supplier-person OR --supplier-org
        self.supplierPerson = ""
        self.supplierOrganization = ""

        # flag: should outputted JSON be pretty-printed?
        # argument: -p / --pretty
        self.pretty = False

    def argparse(self):
        parser = argparse.ArgumentParser()
        parser.add_argument("sources", help="path to list of source files")
        parser.add_argument("srcdir", help="root directory for source files")
        parser.add_argument("builds", help="path to list of build files")
        parser.add_argument("builddir", help="root directory for build files")
        parser.add_argument("-o", "--output", help="path to SPDX output directory")
        parser.add_argument("-n", "--namespace-prefix", help="prefix for SPDX document namespaces")
        parser.add_argument("--package-name", help="package name")
        parser.add_argument("--package-version", help="package version")
        parser.add_argument("--package-license", help="declared license for package")
        supplierGroup = parser.add_mutually_exclusive_group()
        supplierGroup.add_argument("--supplier-person", help="package supplier (person)")
        supplierGroup.add_argument("--supplier-org", help="package supplier (organization)")
        parser.add_argument("-p", "--pretty", help="pretty print JSON output",
                            action="store_true")
        args = parser.parse_args()

        self.sourceList = args.sources
        self.srcdir = args.srcdir
        self.buildList = args.builds
        self.builddir = args.builddir
        if args.output:
            self.outputDir = args.output

        if args.namespace_prefix:
            self.namespacePrefix = args.namespace_prefix
        else:
            self.namespacePrefix = f"http://spdx.org/spdxdocs/{str(uuid.uuid4())}"

        if args.package_name:
            self.packageName = args.package_name
        if args.package_version:
            self.packageVersion = args.package_version
        if args.package_license:
            self.packageDeclaredLicense = args.package_license
        if args.supplier_person:
            self.supplierPerson = args.supplier_person
        if args.supplier_org:
            self.supplierOrganization = args.supplier_org
        if args.pretty:
            self.pretty = True

# Create SPDX Document containing two Packages, sources and builds,
# with all files contained in either, all relationships, and all
# corresponding metadata.
# Arguments:
#   1) sbomConfig: SBOMConfig
#   2) srcPkg: sources Package
#   3) buildPkg: builds Package
def makeSPDXDocument(sbomCfg, srcPkg, buildPkg):
    # prepare Document configuration
    docCfg = DocumentConfig()
    docCfg.name = f"{sbomCfg.packageName} sources and builds"
    docCfg.namespace = sbomCfg.namespacePrefix

    # build Document
    doc = Document(docCfg)

    # add entry and relationship for sources package
    doc.pkgs[srcPkg.cfg.spdxID] = srcPkg
    srcRln = Relationship()
    srcRln.refA = "SPDXRef-DOCUMENT"
    srcRln.refB = srcPkg.cfg.spdxID
    srcRln.rlnType = "DESCRIBES"
    doc.relationships.append(srcRln)

    # add entry and relationship for builds package
    doc.pkgs[buildPkg.cfg.spdxID] = buildPkg
    buildRln = Relationship()
    buildRln.refA = "SPDXRef-DOCUMENT"
    buildRln.refB = buildPkg.cfg.spdxID
    buildRln.rlnType = "DESCRIBES"
    doc.relationships.append(buildRln)

    # add relationship for builds package built from sources package
    sbRln = Relationship()
    sbRln.refA = buildPkg.cfg.spdxID
    sbRln.refB = srcPkg.cfg.spdxID
    sbRln.rlnType = "GENERATED_FROM"
    doc.relationships.append(sbRln)

    return doc

# main entry point for SBOM maker
# Arguments:
#   1) cfg: SBOMConfig
def makeAndWriteSPDX(sbomCfg):
    # ===== sources package =====
    # set up configuration for sources package
    pkgCfgSources = PackageConfig()
    pkgCfgSources.fileListPath = sbomCfg.sourceList
    pkgCfgSources.basedir = os.path.abspath(sbomCfg.srcdir)

    if sbomCfg.packageName:
        pkgCfgSources.name = f"{sbomCfg.packageName} sources"
    else:
        pkgCfgSources.name = f"sources"
    pkgCfgSources.version = sbomCfg.packageVersion
    pkgCfgSources.declaredLicense = sbomCfg.packageDeclaredLicense
    if sbomCfg.supplierOrganization != "":
        pkgCfgSources.supplierOrg = sbomCfg.supplierOrganization
    else:
        pkgCfgSources.supplierPerson = sbomCfg.supplierPerson
    pkgCfgSources.spdxID = "SPDXRef-Package-sources"

    # scan sources file list and build Package and Files metadata
    scanCfgSources = ScannerConfig()
    srcPkg = scanPackage(scanCfgSources, pkgCfgSources)

    # ===== builds package =====
    # set up configuration for builds package
    pkgCfgBuilds = PackageConfig()
    pkgCfgBuilds.fileListPath = sbomCfg.buildList
    pkgCfgBuilds.basedir = os.path.abspath(sbomCfg.builddir)

    if sbomCfg.packageName:
        pkgCfgBuilds.name = f"{sbomCfg.packageName} builds"
    else:
        pkgCfgBuilds.name = f"builds"
    pkgCfgBuilds.version = sbomCfg.packageVersion
    pkgCfgBuilds.declaredLicense = sbomCfg.packageDeclaredLicense
    if sbomCfg.supplierOrganization != "":
        pkgCfgBuilds.supplierOrg = sbomCfg.supplierOrganization
    else:
        pkgCfgBuilds.supplierPerson = sbomCfg.supplierPerson
    pkgCfgBuilds.spdxID = "SPDXRef-Package-builds"

    # scan builds file list and build Package and Files metadata
    scanCfgBuilds = ScannerConfig()
    buildPkg = scanPackage(scanCfgBuilds, pkgCfgBuilds)

    # build single SPDX Document with sources and builds Packages
    doc = makeSPDXDocument(sbomCfg, srcPkg, buildPkg)

    # write document as SPDX JSON
    writeSPDX(sbomCfg.outputDir, doc, sbomCfg.pretty)


if __name__ == "__main__":
    sbomCfg = SBOMConfig()
    sbomCfg.argparse()
    makeAndWriteSPDX(sbomCfg)
