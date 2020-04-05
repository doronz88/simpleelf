import subprocess
import pytest

from simpleelf.elf_builder import ElfBuilder, ElfStructs
from simpleelf import elf_consts

structs = ElfStructs('<')


def verify_in_readelf(filename, output):
    return output in run_shell_cmd(['readelf', '-a' , filename])[0]

def test_build_elf():
    e = ElfBuilder()
    e.set_endianity('<')
    e.set_machine(elf_consts.EM_ARM)

    code = b'CODECODE'

    # add a segment
    text_address = 0x1234
    text_buffer = b'cybercyberbitimbitim' + code
    e.add_segment(text_address, text_buffer, 
        elf_consts.PF_R | elf_consts.PF_W | elf_consts.PF_X)

    # add a second segment
    e.add_segment(0x88771122, b'data in 0x88771122', 
        elf_consts.PF_R | elf_consts.PF_W | elf_consts.PF_X)

    # add a code section inside the first segment
    code_address = text_address + text_buffer.find(code)  # point at CODECODE
    code_size = len(code)
    e.add_code_section('.text', code_address, code_size)

    # set entry point
    e.set_entry(code_address)

    # add .bss section. not requiring a loaded segment from
    # file
    bss_address = 0x5678
    bss_size = 0x200
    e.add_empty_data_section('.bss', bss_address, bss_size)

    elf_raw = e.build()
    parsed_raw_elf = structs.Elf32.parse(elf_raw)

    assert structs.Elf32.build(parsed_raw_elf) == elf_raw, "rebuilt elf is not the same"
