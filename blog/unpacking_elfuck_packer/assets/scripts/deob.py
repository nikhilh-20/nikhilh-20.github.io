#!/usr/bin/python3


import struct
import argparse

from qiling import *
from elftools.elf.elffile import ELFFile


class ELFuckUnpacker():
  '''
  This class unpacks an ELF binary packed with ELFuck packer.
  Capable of unpacking both statically and dynamically-linked
  packed ELF binaries.
  '''

  def __init__(self, fname, rootfs):
    self.phdr_table = None
    self.size = 0
    self.addr = None
    self.memhi = None
    self.magic = b'\x7fELF'
    self.e_phnum = None

    # Will contain the unpacked ELF binary
    self.decompressed_elf = None

    self.deob_elfuck(fname, rootfs)

  def _fix_elf_header(self, fname):
    '''
    This function fixes the ELF header of the packed binary ELF.
    The EI_CLASS and EI_DATA fields are fixed.

    ELFuck operates on 32-bit binaries only, so EI_CLASS must be set to ELFCLASS32.
    The focus is on little-endian systems, so we assume that EI_DATA is ELFDATA2LSB.

    :param fname: The filepath to the ELF binary to emulate
    :type fname: str
    '''

    out_fname = f'{fname}_fixed'
    with open(fname, 'rb') as f:
      data = bytearray(f.read())

    data[4] = data[5] = 0x1

    with open(out_fname, 'wb') as f:
      f.write(data)

    return out_fname

  def _get_elf_metadata(self, fname):
    '''
    This function gets two ELF metadata:

      1. The base image VA
      2. The memory-size of the single PT_LOAD segment

    Base image VA
    -------------
    The base image address is the virtual address of the PT_LOAD segment

    Memory-size of PT_LOAD segment
    ------------------------------
    This is also available in the program header of the PT_LOAD segment

    :param fname: The filepath to the ELF binary to emulate
    :type fname: str
    '''

    base_address = memsz = None
    elffile = ELFFile(open(fname, 'rb'))

    num_segments = len(list(elffile.iter_segments()))
    if num_segments != 1:
      raise Exception('Invalid ELFuckpacker. Expected only 1 segment.')

    for s in elffile.iter_segments():
      if s.header.p_type != 'PT_LOAD':
        raiseException('Invalid ELFuck packer. Expected only 1 segment ' +
               'of type PT_LOAD')

      base_address = s.header.p_vaddr
      memsz = s.header.p_memsz

    if base_address is None or memsz is None:
      raise Exception('Unable to extractbase address or memsz from packed ' +
             'binary ELF header')

    return base_address, memsz

  def _unmap_elf(self, mapped_elf):
    '''
    This function considers the 4096 bytespage-alignment that occurs during
    loading PT_LOAD segments into memory to correct the program header offsets
    in the dumped ELF.

    :param mapped_elf: ELF read from memory during emulation 
    :type mapped_elf: bytearray
    '''

    e_phentsize = 32
    p_type_tracker = []
    pt_interp_length = None
    # ELF header size for a 32-bit ELF binary is 52 bytes
    phdr_table = mapped_elf[52:]
    i = 0

    for phnum in range(self.e_phnum):
      p_type = int.from_bytes(phdr_table[i: i + 4],
                 byteorder='little',signed=False)

      if p_type == 1:
        p_vaddr = phdr_table[i+ 8: i + 12]
        p_vaddr =int.from_bytes(p_vaddr,
                  byteorder='little', signed=False)

        if pt_interp_length:
          p_offset= p_vaddr - self.addr - (pt_interp_length - 1)
        else:
          p_offset= p_vaddr - self.addr

        phdr_table[i + 4: i +8] = p_offset.to_bytes(4, byteorder='little')
      elif p_type == 3:
        # Interesting if PT_LOAD segment was before PT_INTERP
        if 1 in p_type_tracker:
          raiseException('PT_INTERP was found after PT_LOAD segment')
        elif 3 in p_type_tracker:
          raiseException('Multiple PT_INTERP segments found')

        # PT_INTERP occursbefore PT_LOAD
        pt_interp_length =phdr_table[i + 16: i + 20]
        pt_interp_length =int.from_bytes(pt_interp_length,
                       byteorder='little', signed=False)

      p_type_tracker.append(p_type)
      i += e_phentsize

    mapped_elf[52:] = phdr_table
    return mapped_elf 

  def _dump_elf(self, dump_fname):
    '''
    This function first unmaps the ELF binary, i.e., it corrects offsets
    in the program header table. Then it dumps the unmapped ELF binary
    to disk.

    :param dump_fname: The filepath to which unpacked ELF will be dumped.
    :type dump_fname: str
    '''

    if self.decompressed_elf[:4] == self.magic:
      reconstructed_elf =self._unmap_elf(self.decompressed_elf)
    else:
      raise Exception('Unexpected bytes atstart of decompressed region')

    # Nothing more to do here. Dump the binary
    with open(dump_fname, 'wb') as f:
      f.write(reconstructed_elf)

  def hook_all_inst(self, ql, address, size, md):
    '''
    This function is called at the execution of every instruction. It
    looks for the scasb instructions:

    scasb
    -----
    The first scasb instruction that is hit signals the end of decompression
    and start of ELF loading. At this point, the EDI register points to the
    unpacked ELF (which exists after the ELF loader) binary's first program
    header - 1 byte. For statically-linked ELF binaries, this is the
    PT_LOAD segment. For dynamically-linked ELF binaries, this is the
    PT_INTERP segment.

    We also have access to the AUX struct in the ESI register which contains
    information about the location of the program header table, number of
    program headers, and entry point of the unpacked ELF. We use the first
    two information to extract the program header table of the unpacked ELF
    binary.

    :param ql: Qiling instance
    :type ql: qiling.core.Qiling
    :param address: Address of current hooked instruction
    :type address: int
    :param size: Size of current instruction in bytes
    :type size: int
    :param md: Capstone disassembler instance
    :type md: <class 'capstone.Cs'>
    '''

    buf = ql.mem.read(address, size)
    inst_address, inst_size, inst_mnemonic, inst_op_str= \
      next(md.disasm_lite(buf, address))

    if inst_mnemonic != 'scasb':
      return

    # For statically-linked programs, the +1 workswell. For dynamically-
    # linked programs the +1 skips the initial '/'character which we add
    # later while reconstructing the header
    self.addr = ql.arch.regs.read("EDI") + 1
    self.size = self.memhi - self.addr

    self.decompressed_elf = ql.mem.read(self.addr,self.size)
    # self.decompressed_elf either points to the first PT_LOAD segment or
    # the ELF interpreter that was copied at the end of the ELF loader.
    pt_load_start =self.decompressed_elf.index(self.magic)

    if pt_load_start != 0:
      self.decompressed_elf =self.decompressed_elf[pt_load_start:]

    # Ensure PT_LOAD segment
    if self.decompressed_elf[:4] != self.magic:
      raise Exception('Unexpected bytes at start of decompressed region')

    # Get number of entries in the program header table
    self.e_phnum =int.from_bytes(ql.mem.read(ql.arch.regs.read("ESI") + 4, 4),
                  byteorder='little',signed=False)
    ql.emu_stop()

  def deob_elfuck(self, fname, rootfs):
    '''
    This function performs the following functions:
      1. Fixes the EI_CLASS and EI_DATA fields in the packed ELF header.
      2. Extracts the base image virtual address and memory size of the PT_LOAD
         segment.
      3. Instantiates Qiling, sets up hooks and runs the emulation.
      4. Dumps the unpacked binary.

    :param fname: The filepath to the ELF binary to emulate
    :type fname: str
    :param rootfs: The directory path to the x86_linux root filesystem.
                   This is available in the Qiling repository.
    :type rootfs: str
    '''

    # Fix ELF header and dump the fixed ELF binary todisk
    fname = self._fix_elf_header(fname)

    # Get base VA of ELF binary and memory size of PT_LOAD segment
    base_address, memsz = self._get_elf_metadata(fname)

    # Determine the highest page-aligned VA for a PT_LOAD segment of the unpacked binary
    self.memhi = base_address + memsz

    ql = Qiling([fname], rootfs, verbose=4)

    # Trigger hook at every instruction
    ql.hook_code(self.hook_all_inst, user_data=ql.arch.disassembler)
    ql.run()

    # If the unpacked ELF is statically-linked, self.decompressed_elf can be dumped
    # immediately to disk. But dynamically-linked binaries need to be reconstructed.
    self._dump_elf(f'{fname}_unpacked')


if __name__ == '__main__':
  parser = argparse.ArgumentParser()
  parser.add_argument('-f', type=str, required=True, help='File to deobfuscate')
  parser.add_argument('--fs', type=str, required=True, help='Path to x86 Linux rootfs')
  args = parser.parse_args()

  ELFuckUnpacker(args.f, args.fs)
