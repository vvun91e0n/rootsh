## rootsh

rootsh is a local privilege escalation targeting OS X Yosemite 10.10.5 build
14F27. It exploits [CVE-2016-1758] and [CVE-2016-1828], two vulnerabilities in
XNU that were patched in OS X El Capitan [10.11.4] and [10.11.5]. rootsh will
not work on platforms with SMAP enabled.

[CVE-2016-1758]: https://www.cve.mitre.org/cgi-bin/cvename.cgi?name=2016-1758
[CVE-2016-1828]: https://www.cve.mitre.org/cgi-bin/cvename.cgi?name=2016-1828
[10.11.4]: https://support.apple.com/en-us/HT206167
[10.11.5]: https://support.apple.com/en-us/HT206567

### CVE-2016-1758

CVE-2016-1758 is an information leak caused by copying out uninitialized bytes
of kernel stack to user space. By comparing leaked kernel pointers with fixed
reference addresses it is possible to recover the kernel slide.

### CVE-2016-1828

CVE-2016-1828 is a use-after-free during object deserialization. By passing a
crafted binary-serialized dictionary into the kernel, it is possible to trigger
a virtual method invocation on an object with a controlled vtable pointer.

### License

The rootsh code is released into the public domain. As a courtesy I ask that if
you use any of this code in another project you attribute it to me.