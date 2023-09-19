from simpleelf import elf_consts
from simpleelf.elf_builder import ElfBuilder, ElfStructs
from simpleelf.elf_consts import ELFCLASS64

structs = ElfStructs('<')


def test_build_elf32():
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
    e.add_code_section(code_address, code_size, name='.text')

    # set entry point
    e.set_entry(code_address)

    # add .bss section. not requiring a loaded segment from
    # file
    bss_address = 0x5678
    bss_size = 0x200
    e.add_empty_data_section(bss_address, bss_size, name='.bss')

    elf_raw = e.build()
    parsed_raw_elf = structs.Elf32.parse(elf_raw)

    assert structs.Elf32.build(
        parsed_raw_elf) == elf_raw, "rebuilt elf is not the same"


def test_build_elf64():
    e = ElfBuilder(ELFCLASS64)
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
    e.add_code_section(code_address, code_size, name='.text')

    # set entry point
    e.set_entry(code_address)

    # add .bss section. not requiring a loaded segment from
    # file
    bss_address = 0x5678
    bss_size = 0x200
    e.add_empty_data_section(bss_address, bss_size, name='.bss')

    elf_raw = e.build()
    open('/tmp/foo', 'wb').write(elf_raw)
    parsed_raw_elf = structs.Elf64.parse(elf_raw)

    assert structs.Elf64.build(parsed_raw_elf) == elf_raw, "rebuilt elf is not the same"
