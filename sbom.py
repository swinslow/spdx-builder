# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024 Steve Winslow

# Based on zspdx/sbom.py from Zephyr Project:
# Copyright (c) 2020, 2021 The Linux Foundation

import argparse
import os
import uuid

# FIXME TEMP for testing
import sys
from testing import printPackage

from datatypes import PackageConfig
from scanner import ScannerConfig, scanPackage
#from writer import writeSPDX

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
        self.packageName = ""

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

# main entry point for SBOM maker
# Arguments:
#   1) cfg: SBOMConfig
def makeSPDX(sbomCfg):
    # set up configuration for sources package
    pkgCfg = PackageConfig()
    pkgCfg.fileListPath = sbomCfg.sourceList
    # FIXME confirm whether relativeBaseDir is correct
    #pkgCfg.relativeBaseDir = os.path.abspath(os.path.commonpath(filesToScan))
    pkgCfg.basedir = os.path.abspath(sbomCfg.srcdir)

    pkgCfg.name = f"{sbomCfg.packageName} sources"
    pkgCfg.version = sbomCfg.packageVersion
    pkgCfg.declaredLicense = sbomCfg.packageDeclaredLicense
    if sbomCfg.supplierOrganization != "":
        pkgCfg.supplierOrg = sbomCfg.supplierOrganization
    else:
        pkgCfg.supplierPerson = sbomCfg.supplierPerson
    pkgCfg.spdxID = "SPDXRef-Package-sources"

    # scan sources file list and build Package and Files metadata
    scanCfg = ScannerConfig()
    srcPkg = scanPackage(scanCfg, pkgCfg)

    # FIXME TEMP testing
    printPackage(srcPkg)
    sys.exit(1)

    # FIXME add builds package

    # FIXME stopping here to test srcPkg contents
    return srcPkg

    # write each document, in this particular order so that the
    # hashes for external references are calculated

    # write sources document
    writeSPDX(os.path.join(cfg.spdxDir, "sources.spdx"), w.docZephyr)
    if not retval:
        log.err("SPDX writer failed for zephyr document; bailing")
        return False

    # write build document
    writeSPDX(os.path.join(cfg.spdxDir, "build.spdx"), w.docBuild)
    if not retval:
        log.err("SPDX writer failed for build document; bailing")
        return False

    return True

if __name__ == "__main__":
    sbomCfg = SBOMConfig()
    sbomCfg.argparse()
    makeSPDX(sbomCfg)
