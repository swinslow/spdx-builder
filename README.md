# spdx-builder

## Description

Python 3 module for automatically creating an SPDX document (currently
version 2.2) from lists of source files and generated build files.

## Usage

### Minimal command line

```
python3 sbom.py -p -o OUTPUTDIR SRCLIST SRCROOTDIR BUILDLIST BUILDROOTDIR
```

* `-p`: pretty-print JSON output
* `-o OUTPUTDIR`: directory to output generated SPDX Document
* `SRCLIST`: text file listing all source files to include
* `SRCROOTDIR`: path to top directory from which `SRCLIST` paths are relative
* `BUILDLIST`: same as `SRCLIST`, for generated build artifacts
* `BUILDROOTDIR`: same as `SRCROOTDIR`, for generated build artifacts

Additional command line arguments can be used to specify characteristics of the generated SPDX document. Run `python3 sbom.py -h` for a list of all available command line arguments.

### Example usage

```
python3 sbom.py -p -o ~/spdxdocs ~/usbutils/sources.txt ~/usbutils ~/usbutils/builds.txt ~/usbutils
```

This example assumes that:

* `~/usbutils` contains the project being analyzed, which has already been built
* `~/usbutils/sources.txt` is a text file that lists all source code files used in the build, 1 file per line, as relative paths
* `~/usbutils/builds.txt` is similar, listing each file generated during the build
* the SPDX document will be created at `~/spdxdocs/doc.spdx.json`

## Dependencies

None beyond the Python 3 standard library.

## License

Apache-2.0
