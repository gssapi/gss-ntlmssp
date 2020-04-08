# Release Process for GSS-NTLMSSP

The process is currently quite simple and requires write access to the project's git repository.

## Prepare the sources

### Version and Tag the release

* Commit a change in version.m4 with the new version number
  (ex. 0.1.0)
* Test locally with "make rpms" that everything builds fine
* Tag the release in master like this:
```
git tag v0.1.0
```
  This will apply the tag to the last commit

* Push the tag:
```
git push origin v0.1.0
```

### Create a release tarball and SHA hash

* Run the following commands (on a git clean tree, please):
```
autoreconf -f -i
./configure
make dist
```
  ... will generate a tarball named like: gssntlmssp-0.1.0.tar.gz
```
sha512sum gssntlmssp-0.1.0.tar.gz > gssntlmssp-0.1.0.tar.gz.sha512sum.txt
```
  ... will generate a file with a sha512 checksum

### Publish the release

* Upload the tarball and checksum on the release page
