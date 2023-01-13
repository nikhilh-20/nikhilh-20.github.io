__version__   = "1.0"
__author__    = "Nikhil Ashok Hegde <ka1do9>"

import logging

import idc
import ida_ua
import ida_xref
import idautils
import ida_bytes
import ida_segment

from pprint import pprint
LOG = logging.getLogger()
LOG.setLevel(logging.DEBUG)

def _print_address_list(addresses):
    for addr in addresses:
        LOG.debug(hex(addr))
    LOG.debug("\n")


def find_offset_cross_references(addr, possible_string_start_addr={}):
    """
    Given an address, this function determines if there are any and only OFFSET-type
    cross references to the said address. Switch jump tables also exist in the .rodata
    section and we are not interested in those. I've observed that the address of the
    start of the jump table has a READ-type cross reference. So, I focus only on
    OFFSET-type cross reference.
    
    FUTURE IMPROVEMENTS
    ===================
    I've come across code where a string address is "mov'd" into a register and the
    string length is the imm value in the ensuing "add" instruction. These kinds of
    strings are not printed by this script.
    
    Strings embedded in the .text section are not printed by this script. This script
    only looks at strings in the .rodata section.
    """

    xref_to = None
    xref_found = False
    non_offset_xref = False

    for xref in idautils.XrefsTo(addr):
        if xref.type == ida_xref.dr_O:
            xref_to = xref.to
            xref_found = True
        else:
            non_offset_xref = True
            break

    if xref_found and non_offset_xref:
        LOG.debug("SKIP: A non-offset xref was also found to addr: " + hex(addr))
    elif not xref_found:
        LOG.debug("SKIP: No xrefs were found to addr: " + hex(addr))
    else:
        possible_string_start_addr.add(xref_to)
    
    return possible_string_start_addr


def traverse_rodata(rodata_start_addr, rodata_end_addr):
    """
    Iterate from start of .rodata segment till the end of the segment to find addresses
    which may be the start of a string.
    """
    
    possible_string_start_addr = set()
    
    # Go through all .rodata addresses and check which addresses have an offset-type
    # cross-reference to them. String literals in the binary are always going to be
    # loaded by address.
    for addr in range(rodata_start_addr, rodata_end_addr, 0x1):
        # Check if OFFSET-type cross reference exists at this address. If so, it is a possibly a
        # start addresses of a string
        possible_string_start_addr = find_offset_cross_references(addr, possible_string_start_addr)

    # Sort addresses in ascending order. The difference in addresses at x[n+1] and x[n] will
    # be the maximum length of the string at address x[n]
    possible_string_start_addr = sorted(possible_string_start_addr)
    _print_address_list(possible_string_start_addr)
    
    return possible_string_start_addr


def get_len_string(addr):
    """
    Given an address where the OFFSET-type cross-reference is from, there are two scenarios:
    
    ### DIRECT REFERENCE IN CODE ###
    
    In this case, this function looks at the previous/next 3 instructions to find an instruction of format:
    
    mov <register> <imm>
    
    If so, it checks if the <imm> value is <= the maximum string length at the said string address. If so, <imm>
    value is considered the length of the string at the said address.
    
    ### REFERENCE IN DATA ###
    
    In this case, this function checks if the data reference is in the ".data.rel.ro segment. If so, it expects
    a string slice structure at the referenced address. The first member is the ptr to the string literal and
    the second member is the length of the string literal.
    """
    
    num_insn_check = 3
    flags = ida_bytes.get_flags(addr)
    iscode = ida_bytes.is_code(flags)

    if iscode:
        # Code cross-reference
        insn = ida_ua.insn_t()
        ida_ua.decode_insn(insn ,addr)
        mnem = insn.get_canon_mnem()
        if mnem.lower() == "lea":
            curr_addr = addr
            # Iterate next few instructions trying to find a "mov" instruction
            # and then returning the second operand, assuming it's the length
            while num_insn_check > 0:
                curr_addr = ida_bytes.next_head(curr_addr, idc.get_segm_end(addr))
                ida_ua.decode_insn(insn ,curr_addr)
                mnem = insn.get_canon_mnem()
                if mnem.lower() == "mov":
                    if insn.Op2.type == ida_ua.o_imm:
                        return insn.Op2.value
                num_insn_check -= 1
            # Iterate previous few instructions trying to find a "mov" instruction
            # and then returning the second operand, assuming it's the length
            curr_addr = addr
            while num_insn_check < 3:
                curr_addr = ida_bytes.prev_head(curr_addr, idc.get_segm_start(addr))
                ida_ua.decode_insn(insn ,curr_addr)
                mnem = insn.get_canon_mnem()
                if mnem.lower() == "mov":
                    if insn.Op2.type == ida_ua.o_imm:
                        return insn.Op2.value
                num_insn_check += 1
        # At this point, the target "mov" instruction was not found above. Some "mov" instruction
        # move the length of the string from a stack variable rather than an immediate value. In
        # such cases, I'll need to track that stack variable's value and I'm not working so hard.
        # So, I'll just return -1 here which means - consider the maximum length
        return -1
    else:
        # Data cross-reference
        if idc.get_segm_name(addr).lower() == ".data.rel.ro":
            # Structure of a string slice is
            # {
            #   _QWORD ptr;
            #   _QWORD len;
            # }
            # <addr> currently points to the first member of the structure, so
            # the next defined address must be the length of the string.
            len_addr = addr + 8
            #len_addr = ida_bytes.next_head(addr, idc.get_segm_end(addr))
            return int.from_bytes(idc.get_bytes(len_addr, 8), byteorder="little")

    return 0


def get_unicode_str(addr, len_):
    bytes_ = idc.get_bytes(addr, len_)
    try:
        utf_8_str = bytes_.decode("utf-8")
        LOG.info(f"{hex(addr)}: {utf_8_str}")
        return utf_8_str
    except UnicodeDecodeError:
        return ""


def create_strings(possible_string_start_addr, rodata_end_addr):
    """
    This function iterates through the possible string addresses list. For each string, it determines its length.
    It determines the unicode string present at that address with the calculated length. Then it creates the
    string at the specified address with that length.
    """
    
    utf_8_str_set = set()

    for i in range(0, len(possible_string_start_addr) - 1):
        str_start_addr = possible_string_start_addr[i]
        str_end_addr = possible_string_start_addr[i+1]
        max_str_len = str_end_addr - str_start_addr
        
        # For the same string slice, different xrefs code may slice different lengths of the string
        # literal. That's the reason, I go through all xrefs rather than just one.
        for xref in idautils.XrefsTo(str_start_addr):
            # No need to check for OFFSET-type cross reference. That's already done.
            str_len = get_len_string(xref.frm)
            if str_len == -1:
                str_len = max_str_len
            if str_len and str_len <= max_str_len:
                utf_8_str = get_unicode_str(str_start_addr, str_len)
                utf_8_str_set.add(utf_8_str)
                '''
                # I don't know how to create Unicode strings in IDAPython. However it is, it'll
                # have to be plugged here
                status = ida_bytes.create_strlit(str_start_addr, str_len)
                if status:
                    LOG.info("SUCCESS: String: \"" + idc.get_strlit_contents(str_start_addr, str_len).decode() +
                          "\" created at address: " + hex(str_start_addr))
                else:
                    LOG.debug("SKIP: Failed to create string at address: " + hex(str_start_addr))
                '''

    return utf_8_str


def print_strings():
    rodata_start_addr = None
    rodata_end_addr = None

    # Rust has strings in .rodata section, so get the start and end address to that segment.
    for ea in Segments():
        if idc.get_segm_name(ea).lower() == ".rodata":
            rodata_start_addr = ea
            rodata_end_addr = idc.get_segm_end(rodata_start_addr)
            break
    LOG.info(".rodata start addr: " + hex(rodata_start_addr))
    LOG.info(".rodata end addr: " + hex(rodata_end_addr))

    # Get a list of addresses each of which *possibly* signifies the start of a string
    possible_string_start_addr = traverse_rodata(rodata_start_addr, rodata_end_addr)
    return create_strings(possible_string_start_addr, rodata_end_addr)
    

if __name__ == "__main__":
    print_strings()
