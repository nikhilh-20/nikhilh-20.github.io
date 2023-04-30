# Unpacking the ELFuck Packer

[elfuck](https://github.com/timhsutw/elfuck) is an open-source packer for 32-bit ELF executables. and is written mostly in C and x86 assembly. It uses custom code to load the original binary into memory for execution. NRV2E algorithm is used to compress the loader and the original binary contents. The unpacking stub decompresses and executes the loader and the original binary contents at runtime in memory.

ELFuck has three main features which can be used in combination with each other:
* compression with NRV2E
* polymorphic scrambler, and
* a password-based binary locking mechanism.

[This paper](./assets/files/unpacking_elfuck.pdf) describes the packing technique and the polymorphic scrambler used by ELFuck, and contributes an [unpacking program](./assets/scripts/deob.py) written in the Python language. The unpacking tool leverages the Qiling framework for emulating the packed binary. I do not explore the password-based binary locking feature because it is generally not leveraged by malware, which are intended to execute autonomously. I also primarily focus on malware which are targeted to little-endian systems.


## Usage/Example

```bash
$ python3 deob.py -f hello_world_dynamic_packed_poly --fs ~/qiling/examples/rootfs/x86_linux
[+] Profile: Default
[+] Map GDT at 0x30000 with GDT_LIMIT=4096
[+] Write to 0x30018 for new entry
b'\x00\xf0\x00\x00\x00\xfeO\x00'
[+] Write to 0x30028 for new entry
b'\x00\xf0\x00\x00\x00\x96O\x00'
[+] Mapped 0x8046000-0x804b000
[+] mem_start : 0x8046000
[+] mem_end : 0x804b000
[+] mmap_address is : 0x774bf000

$ chmod +x
hello_world_dynamic_packed_poly_fixed_unpacked

$ ./hello_world_dynamic_packed_poly_fixed_unpacked
Hello World!
```