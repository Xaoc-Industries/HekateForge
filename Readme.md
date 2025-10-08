**HekateForge Construct**

*This construct is a patent pending system for obfuscation*
*This system is property of William Appleton*

**Contact William@XaocIndustries.com for commercial inquiries**

**USAGE**

*dd if=/path/to/file | hekateforge encode $key > /path/to/output.pld*

*dd if=/path/to/pld | hekateforge decode $key > /path/to/recovered/file*

$key should be a base64 representation of 4KB of random data (4096 Bytes)

I find that:

*key=$(dd if=\dev\zero bs=1 count=4096 | base64 -w 0)*

works well for key generation.

***HekateForge is patent pending as of June 27 2025***
**All rights reserved**
