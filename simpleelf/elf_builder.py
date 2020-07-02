from collections import namedtuple

from construct import *

from simpleelf.elf_structs import ElfStructs
from simpleelf import elf_consts

class ElfBuilder:
    Segment = namedtuple('Segment', ['address', 'flags', 'contents'])
    Section = namedtuple('Section', ['type', 'name', 'address', 'flags', 'size'])

    def __init__(self):
        self._segments = []
        self._sections = []
        self._machine = 0
        self._entry = 0
        self._endianity = '<'
        self._structs = ElfStructs(self._endianity)
        self._e_ehsize = self._structs.Elf32_Ehdr.sizeof()
        self._e_phoff = self._e_ehsize
        self._e_phentsize = 0x20  # TODO: calculate according to the struct
        self._e_shentsize = 0x28  # TODO: calculate according to the struct
        self._e_phnum = 0
        self._e_shnum = 0
        self._e_shoff = self._e_phoff + self._e_phentsize * self._e_phnum
        self._strtab_text = b'\x00.strtab\x00'

        self.add_section(self._structs.Elf_SectionType.SHT_NULL, 0,
            0, 0, 0)

    def set_endianity(self, endianity):
        self._endianity = endianity
        self._structs = ElfStructs(endianity)        

    def add_segment(self, address, contents, flags):
        self._e_phnum += 1
        self._e_shoff += self._e_phentsize + len(contents)

        segment = self.Segment(address=address,
           flags=flags,
           contents=contents)

        self._segments.append(segment)

    def find_loaded_data(self, address, size=None):
        offset = self._e_phoff
        data = None

        for segment in self._segments:
            # skip program header
            offset += self._e_phentsize

            if (segment.address <= address) and (segment.address + len(segment.contents) >= address):
                offset += address - segment.address
                data = segment.contents[address - segment.address:]
            else:
                if data is None:
                    # skip current segment contents
                    offset += len(segment.contents)

        if data is None:
            return None

        if size is not None:
            data = data[:size]

        return offset, data

    def add_section(self, type_, address, size, name, flags):
        if name is not None:
            if type(name) is str:
                self._strtab_text += name.encode() + b'\x00'

        # create segment for the section if necessary
        if type_ in (self._structs.Elf_SectionType.SHT_PROGBITS, ):
            if self.find_loaded_data(address) is None:
                raise Exception("section of type SHT_PROGBITS not inside any segment")

        section = self.Section(
            name=name,
            type=type_,
            address=address, 
            size=size, 
            flags=flags)

        self._e_shnum += 1
        self._sections.append(section)

    def add_code_section(self, name, address, size):
        self.add_section(self._structs.Elf_SectionType.SHT_PROGBITS, address, size,
            name, elf_consts.SHF_ALLOC | elf_consts.SHF_EXECINSTR)

    def add_empty_data_section(self, name, address, size):
        self.add_section(self._structs.Elf_SectionType.SHT_NOBITS, address, size, 
            name, elf_consts.SHF_ALLOC | elf_consts.SHF_WRITE)

    def _add_string_section(self):
        self.add_section(self._structs.Elf_SectionType.SHT_STRTAB, 0, 
            len(self._strtab_text), 1, elf_consts.SHF_ALLOC)

    def set_machine(self, machine):
        self._machine = machine

    def set_entry(self, entry):
        self._entry = entry

    def build(self):
        structs = self._structs

        # append strtab as the last section
        self._add_string_section()

        if self._endianity == '<':
            e_ident_data = elf_consts.ELFDATA2LSB
        else:
            e_ident_data = elf_consts.ELFDATA2MSB

        elf = {
            'header': {
                'e_ident': {
                    'magic': elf_consts.ELFMAG,
                    'class': elf_consts.ELFCLASS32,
                    'data': e_ident_data,
                    'osabi': elf_consts.ELFOSABI_NONE,
                    'pad': Padding(8),
                },
                'e_type': elf_consts.ET_EXEC,
                'e_machine': self._machine,
                'e_version': elf_consts.EV_CURRENT,
                'e_entry': self._entry,
                'e_phoff': self._e_phoff,
                'e_shoff': self._e_shoff + len(self._strtab_text),
                'e_flags': 0,
                'e_ehsize': self._e_ehsize,
                'e_phentsize': self._e_phentsize,
                'e_phnum': self._e_phnum,
                'e_shentsize': self._e_shentsize,
                'e_shnum': self._e_shnum,
                'e_shstrndx': self._e_shnum - 1,
            },
            'segments': [],
            'sections': [],
        }

        # add segments
        segment_data_offset = self._e_phoff + self._e_phnum * self._e_phentsize

        for segment in self._segments:
            elf['segments'].append({
                'p_type': self._structs.Elf_SegmentType.PT_LOAD,
                'p_offset': segment_data_offset,
                'p_vaddr': segment.address,
                'p_paddr': segment.address,
                'p_filesz': len(segment.contents),
                'p_memsz': len(segment.contents),
                'p_flags': segment.flags,
                'p_align': 0x20,
                'data': segment.contents
            })
            segment_data_offset += len(segment.contents)

        end_of_segments_offset = segment_data_offset

        # add sections
        for section in self._sections:
            if section.name is None:
                sh_name = elf_consts.SHN_UNDEF
            else:
                if type(section.name) is int:
                    sh_name = section.name
                else:
                    sh_name = self._strtab_text.find(section.name.encode() + b'\x00')

            if section.type == self._structs.Elf_SectionType.SHT_PROGBITS:
                size = section.size
                offset, contents = self.find_loaded_data(section.address, size)
            else:  
                # every non-loaded data into memory, which resides only in ELF
                # will be pointed by `end_of_segments_offset`.
                # we can append data there
                offset = end_of_segments_offset

                if section.type == self._structs.Elf_SectionType.SHT_STRTAB:
                    # the string table is object-globalized
                    contents = self._strtab_text
                    size = len(contents)
                else:
                    # .bss section for example, where place in memory is just
                    # allocated with no specific data
                    contents = b''
                    size = section.size

                if section.type != self._structs.Elf_SectionType.SHT_NOBITS:
                    end_of_segments_offset += size

            elf['sections'].append({
                'sh_name': sh_name,
                'sh_type': section.type,
                'sh_flags': section.flags,
                'sh_addr': section.address,
                'sh_offset': offset,
                'sh_size': size,
                'sh_link': 0,
                'sh_info': 0,
                'sh_addralign': 0x20,
                'sh_entsize': 0,
                'data': contents
            })

        return structs.Elf32.build(elf)

