# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024 Steve Winslow

def printPackage(pkg):
    print(f"===== TESTING: package details =====")
    print(f"Package config name: {pkg.cfg.name}")
    print(f"Package config fileListPath: {pkg.cfg.fileListPath}")
    print(f"Package config basedir: {pkg.cfg.basedir}")
    print(f"Package config spdxID: {pkg.cfg.spdxID}")
    print(f"Package verificationCode: {pkg.verificationCode}")
    print(f"")

    print(f"Package files:")
    for k, v in pkg.files.items():
        print(f"* {k}:")
        print(f"  - relpath:           {v.relpath}")
        print(f"  - abspath:           {v.abspath}")
        print(f"  - SHA1:              {v.sha1}")
        print(f"  - SHA256:            {v.sha256}")
        print(f"  - concludedLicense:  {v.concludedLicense}")
        print(f"  - licenseInfoInFile: {','.join(v.licenseInfoInFile)}")
