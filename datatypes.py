# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024 Steve Winslow

# Based on zspdx/datatypes.py from Zephyr Project:
# Copyright (c) 2021 The Linux Foundation

# DocumentConfig contains settings used to configure how the SPDX Document
# should be built.
class DocumentConfig:
    def __init__(self):
        super(DocumentConfig, self).__init__()

        # name of document
        self.name = ""

        # namespace for this document
        self.namespace = ""

        # standardized DocumentRef- (including that prefix) that the other
        # docs will use to refer to this one
        self.docRefID = ""

# Document contains the data assembled by the SBOM builder, to be used to
# create the actual SPDX Document.
class Document:
    # initialize with a DocumentConfig
    def __init__(self, cfg):
        super(Document, self).__init__()

        # configuration - DocumentConfig
        self.cfg = cfg

        # dict of SPDX ID => Package
        self.pkgs = {}

        # relationships "owned" by this Document, _not_ those "owned" by its
        # Packages or Files; will likely be just DESCRIBES
        self.relationships = []

        # set of other Documents that our elements' Relationships refer to
        self.externalDocuments = set()

        # set of LicenseRef- custom licenses to be declared
        # may or may not include "LicenseRef-" license prefix
        self.customLicenseIDs = set()

        # this Document's SHA1 hash, filled in _after_ the Document has been
        # written to disk, so that others can refer to it
        self.myDocSHA1 = ""

# PackageConfig contains settings used to configure how an SPDX Package should
# be built.
class PackageConfig:
    def __init__(self):
        super(PackageConfig, self).__init__()

        # path to text file listing all paths of files contained in this Package
        self.fileListPath = ""

        # absolute path of the "root" directory on disk, to be used as the
        # base directory from which this Package's Files will calculate their
        # relative paths
        self.basedir = ""

        # package name
        self.name = ""

        # package version
        self.version = ""

        # package supplier - either Person or Organization, but not both
        self.supplierPerson = ""
        self.supplierOrg = ""

        # SPDX ID, including "SPDXRef-"
        self.spdxID = ""

        # the Package's declared license
        self.declaredLicense = "NOASSERTION"

        # the Package's copyright text
        self.copyrightText = "NOASSERTION"

# Package contains the data assembled by the SBOM builder, to be used to
# create the actual SPDX Package.
class Package:
    # initialize with:
    # 1) PackageConfig
    def __init__(self, cfg):
        super(Package, self).__init__()

        # configuration - PackageConfig
        self.cfg = cfg

        # Document that owns this Package
        self.doc = None

        # verification code, calculated per section 3.9 of SPDX spec v2.2
        self.verificationCode = ""

        # concluded license for this Package, if
        # cfg.shouldConcludePackageLicense == True; NOASSERTION otherwise
        self.concludedLicense = "NOASSERTION"

        # list of licenses found in this Package's Files
        self.licenseInfoFromFiles = []

        # Files in this Package
        # dict of SPDX ID => File
        self.files = {}

        # Relationships "owned" by this Package (e.g., this Package is left
        # side)
        self.rlns = []

# File contains the data needed to create a File element in the context of a
# particular SPDX Document and Package.
class File:
    # initialize with:
    # 1) Package containing this File
    def __init__(self, pkg):
        super(File, self).__init__()

        # absolute path to this file on disk
        self.abspath = ""

        # relative path for this file, measured from the owning
        # Package's basedir
        self.relpath = ""

        # SPDX ID for this file, including "SPDXRef-"
        self.spdxID = ""

        # SHA1 hash
        self.sha1 = ""

        # SHA256 hash, if pkg.cfg.doSHA256 == True; empty string otherwise
        self.sha256 = ""

        # concluded license, if pkg.cfg.shouldConcludeFileLicenses == True;
        # "NOASSERTION" otherwise
        self.concludedLicense = "NOASSERTION"

        # license info in file
        self.licenseInfoInFile = []

        # copyright text
        self.copyrightText = "NOASSERTION"

        # Relationships "owned" by this File (e.g., this File is left side)
        self.rlns = []

        # Package that owns this File
        self.pkg = pkg

        # Document that owns this File
        self.doc = None
