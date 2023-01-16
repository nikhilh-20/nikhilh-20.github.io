__version__   = "1.0"
__author__    = "Nikhil Ashok Hegde <ka1do9>"

import dnfile
import argparse

from dnfile.enums import MetadataTables
from dncil.cil.opcode import OpCodes
from dncil.cil.body import CilMethodBody
from dncil.cil.body.reader import CilMethodBodyReaderBase
from dncil.clr.token import InvalidToken


class DnfileMethodBodyReader(CilMethodBodyReaderBase):
    """
    Borrowed from
    https://github.com/mandiant/dncil/blob/6bf3066e2f23c662ad57918f7992e0f70928ca02/scripts/print_cil_from_dn_file.py#L30-L49
    """
    def __init__(self, pe, row):
        """
        :param pe: dnfile object of the sample
        :type pe: <class 'dnfile.dnPE'>
        :param row: A row entry from the MethodDef table
        :type row: <class 'dnfile.mdtable.MethodDefRow'>
        """
        self.pe = pe
        self.file_offset = self.pe.get_offset_from_rva(row.Rva)

    def read(self, n):
        """
        Read n bytes from the sample starting from a specified file offset.

        :param n: Number of bytes to read
        :type n: int
        :return: File content of length n bytes
        :rtype: <class 'bytes'>
        """
        data = self.pe.get_data(self.pe.get_rva_from_offset(self.file_offset), n)
        self.file_offset += n
        return data

    def tell(self):
        """
        Determines the current position of the file pointer in the file stream

        :return: Current position of the file pointer
        :rtype: int
        """
        return self.file_offset

    def seek(self, offset):
        """
        Changes the current position of the file pointer in the file stream
        to a given offset.

        :param offset: File offset to change the current position of the
                       file pointer to
        :param offset: int
        :return: Current file offset pointer
        :rtype: int
        """
        self.file_offset = offset
        return self.file_offset


def resolve_token(pe, token, dotnet_meta_tables_by_index):
    """
    Get the token object entry from its metadata table. Borrowed from
    https://github.com/mandiant/dncil/blob/6bf3066e2f23c662ad57918f7992e0f70928ca02/scripts/print_cil_from_dn_file.py#L70-L84

    :param pe: dnfile object of the sample
    :type pe: <class 'dnfile.dnPE'>
    :param token: Managed token
    :type token: <class 'dncil.clr.token.Token'>
    :param dotnet_meta_tables_by_index: .NET metadata tables
    :type dotnet_meta_tables_by_index: dict
    :return: Row object in a metadata table or InvalidToken
    :rtype: <class 'dnfile.mdtable.MemberRefRow'> or <class 'type'>
    """
    # Get metadata table from token table index
    table_name = dotnet_meta_tables_by_index.get(token.table, "")
    if not table_name:
        return InvalidToken(token.value)

    metadata_table = getattr(pe.net.mdtables, table_name, None)
    if metadata_table is None:
        return InvalidToken(token.value)

    try:
        # RID is 1-index. metadata_table.rows is 0-indexed.
        return metadata_table.rows[token.rid - 1]
    except IndexError:
        return InvalidToken(token.value)


def get_token_rva(pe, insn, dotnet_meta_tables_by_index):
    """
    Get the RVA of the given token

    :param pe: dnfile object of the sample
    :type pe: <class 'dnfile.dnPE'>
    :param insn: Instruction object
    :type insn: <class 'dncil.cil.instruction.Instruction'>
    :param dotnet_meta_tables_by_index: Index to metadata table name mapping
    :type dotnet_meta_tables_by_index: dict
    :return: RVA of token
    :rtype: int
    """
    rva = None
    ldtoken_operand = resolve_token(pe, insn.operand,
                                    dotnet_meta_tables_by_index)
    # fdHasFieldRVA flag is set when a token, like the int array,
    # has an initial value
    if ldtoken_operand.Flags.fdHasFieldRVA:
        # One of the following tokens should point to the same blob
        # object as ldtoken_operand
        for token in pe.net.mdtables.FieldRva:
            if token._blobs == ldtoken_operand._blobs:
                rva = token.Rva

    return rva


def get_parameters_traverse_body(pe, body, dotnet_meta_tables_by_index):
    """
    Read the body of a function and look for the specific ldtoken instruction
    that loads the int array.

    :param pe: dnfile object of the sample
    :type pe: <class 'dnfile.dnPE'>
    :param body: Body of a function
    :type body: <class 'dnfile.mdtable.MethodDefRow'>
    :param dotnet_meta_tables_by_index: Index to metadata table name mapping
    :type dotnet_meta_tables_by_index: dict
    :return: RVA, Length of int array and XOR-decryption key
    :rtype: Tuple of int or tuple of None
    """
    rva = None
    xor_key = None
    int_array_len = None
    most_recent_ldc_insn = None

    for i, insn in enumerate(body.instructions):
        if (insn.get_mnemonic() == OpCodes.Call.name and
                body.instructions[i-1].get_mnemonic() == OpCodes.Ldtoken.name):
            # Call instruction found immediately after ldtoken instruction
            # as expected

            # The most recent LDC_I4 instruction will hold the length of the
            # int array
            if most_recent_ldc_insn:
                # Get length of the int array
                int_array_len = most_recent_ldc_insn.operand

            # Get token object from the relevant
            # metadata table.
            call_operand_token = resolve_token(pe, insn.operand,
                                               dotnet_meta_tables_by_index)
            # Since we're looking for a referenced method, the token object
            # must be in the MemberRef metadata table.
            if isinstance(call_operand_token, dnfile.mdtable.MemberRefRow):
                if (call_operand_token.Class.row.TypeName == "RuntimeHelpers" and
                        call_operand_token.Name == "InitializeArray"):
                    # The previous ldtoken instruction is relevant
                    rva = get_token_rva(pe, body.instructions[i-1],
                                        dotnet_meta_tables_by_index)
        elif insn.get_mnemonic() == OpCodes.Ldc_I4.name:
            most_recent_ldc_insn = insn

    # The last LDC_I4 instruction will contain the xor key
    if most_recent_ldc_insn:
        xor_key = most_recent_ldc_insn.operand

    return rva, int_array_len, xor_key


def get_parameters(pe, dotnet_meta_tables_by_index):
    """
    Traverse the MethodDef table, find relevant instructions and determine
    the parameters useful for deobfuscating the strings.

    :param pe: dnfile object of the sample
    :type pe: <class 'dnfile.dnPE'>
    :param dotnet_meta_tables_by_index: Index to metadata table name mapping
    :type dotnet_meta_tables_by_index: dict
    :return: File offset, Length of int array and XOR-decryption key
    :rtype: Tuple of int or tuple of None
    """
    for row in pe.net.mdtables.MethodDef:
        if not row.ImplFlags.miIL or any((row.Flags.mdAbstract, row.Flags.mdPinvokeImpl)):
            # "miIL" indicates that the method is implemented with Intermediate
            # Language (IL) code. "mdAbstract" indicates an abstract method.
            # "mdPinvokeImpl" indicates a method implemented with Platform
            # Invocation Services (PInvoke). Its implementation lies elsewhere.
            # Skip above type of methods.
            continue

        if not row.Flags.mdRTSpecialName:
            # The int array is expected to exist inside the class constructor
            continue

        body = CilMethodBody(DnfileMethodBodyReader(pe, row))
        if not body.instructions:
            # Empty body
            continue

        # Get the specific ldtoken instruction that loads the int array
        rva, int_array_len, xor_key = \
            get_parameters_traverse_body(pe, body, dotnet_meta_tables_by_index)

        if rva and int_array_len and xor_key:
            # This block should be entered only once, if obfuscator is as
            # expected.
            return pe.get_offset_from_rva(rva), int_array_len, xor_key

    return None, None, None


def find_insn_load_value(insn):
    """
    Returns the load value of LDC_I4* instructions.

    :param insn: Instruction object
    :type insn: <class 'dncil.cil.instruction.Instruction'>
    :return: Load value of LDC_I4* instruction
    :rtype: int
    """
    mnemonic = insn.get_mnemonic()
    val_map = {
        OpCodes.Ldc_I4_0.name: 0,
        OpCodes.Ldc_I4_1.name: 1,
        OpCodes.Ldc_I4_2.name: 2,
        OpCodes.Ldc_I4_3.name: 3,
        OpCodes.Ldc_I4_4.name: 4,
        OpCodes.Ldc_I4_5.name: 5,
        OpCodes.Ldc_I4_6.name: 6,
        OpCodes.Ldc_I4_7.name: 7,
        OpCodes.Ldc_I4_8.name: 8,
    }

    if mnemonic in (OpCodes.Ldc_I4.name, OpCodes.Ldc_I4_S.name):
        return insn.operand
    elif mnemonic in val_map:
        return val_map[mnemonic]


def get_string_slicer_traverse_body(body):
    """
    Read the body of a function and look for the specific ldtoken instruction
    that loads the int array.

    :param body: Body of a function
    :type body: <class 'dnfile.mdtable.MethodDefRow'>
    :return: Offset of string slice in string stream, Length of slice
    :rtype: Tuple of int or tuple of None
    """
    ldc_i4 = "ldc.i4"
    offset, length = None, None

    for i, insn in enumerate(body.instructions):
        if (insn.get_mnemonic() == OpCodes.Call.name and
                # There are many types of ldc.i4 instructions
                # ldc.i4.0, ldc.i4.1, etc. Hardcoded string check seems to be the
                # easiest first-level check
                ldc_i4 in body.instructions[i-1].get_mnemonic() and
                ldc_i4 in body.instructions[i-2].get_mnemonic() and
                ldc_i4 in body.instructions[i-3].get_mnemonic()):
            # Call instruction found immediately after 3 LDC_I4* instructions
            # as expected

            length = find_insn_load_value(body.instructions[i-1])
            offset = find_insn_load_value(body.instructions[i-2])
            return offset, length

    return offset, length


def get_parameters_traverse_string_slicers(pe):
    """
    Traverse the MethodDef table, find relevant instructions and determine
    the offsets that are used to slice the string stream.

    :param pe: dnfile object of the sample
    :type pe: <class 'dnfile.dnPE'>
    :return: Offset of all string slices in string stream, Length of all slices
    :rtype: Tuple of lists of int or tuple of lists of None
    """
    offsets = []
    lengths = []

    for row in pe.net.mdtables.MethodDef:
        if not row.ImplFlags.miIL or any((row.Flags.mdAbstract, row.Flags.mdPinvokeImpl)):
            continue

        if row.Flags.mdRTSpecialName:
            # String slicers are not expected inside the constructor
            continue

        body = CilMethodBody(DnfileMethodBodyReader(pe, row))
        if not body.instructions:
            continue

        offset, length = get_string_slicer_traverse_body(body)
        if offset is not None and length is not None:
            offsets.append(offset)
            lengths.append(length)

    return offsets, lengths


def deobfuscate_strings(fpath):
    """
    Main function.

    :param fpath: Full on-disk path to .NET sample
    :type fpath: str
    :return: Deobfuscated strings
    :rtype: List of str
    """
    deobfuscated_strings = []
    dotnet_meta_tables_by_index = {table.value: table.name
                                   for table in MetadataTables}
    pe = dnfile.dnPE(fpath)

    # Get parameters of int array
    offset, length, xor_key = get_parameters(pe, dotnet_meta_tables_by_index)
    print(f"RVA of int array: {hex(offset)}, "
          f"Length of int array:  {hex(length)}, "
          f"XOR key to decrypt strings: {xor_key}")

    with open(fpath, "rb") as f:
        data = f.read()
    obfuscated_strings_stream = data[offset: offset + length]

    # Decrypt strings
    string_stream = ""
    for i, data in enumerate(obfuscated_strings_stream):
        string_stream += chr((i & 0xFF) ^ data ^ xor_key)

    # Traverse through string slicer functions and get offset, length of each string slice
    offsets, lengths = get_parameters_traverse_string_slicers(pe)

    # Get it all together
    for offset, length in zip(offsets, lengths):
        deobfuscated_strings.append(string_stream[offset: offset + length])

    return deobfuscated_strings


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", type=str, required=True,
                        help="Path to .NET binary")
    args = parser.parse_args()
    print(deobfuscate_strings(args.file))
