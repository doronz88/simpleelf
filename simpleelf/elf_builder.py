from collections import namedtuple

from construct import *

from simpleelf.elf_structs import ElfStructs
from simpleelf import elf_consts

class ElfBuilder:
    Segment = namedtuple('Segment', ['address', 'flags', 'size'])
    Section = namedtuple('Section', ['type', 'name', 'address', 'contents', 'flags', 'size'])

    def __init__(self):
        self._segments = []
        self._sections = []
        self._machine = 0
        self._entry = 0
        self._endianity = '<'
        self._structs = ElfStructs(self._endianity)
        self._e_ehsize = self._structs.Elf32_Ehdr.sizeof()
        self._e_phoff = self._e_ehsize
        self._e_phentsize = self._structs.Elf32_Phdr.sizeof()
        self._e_shentsize = 0x28  # TODO: calculate according to the struct
        self._e_phnum = 0
        self._e_shnum = 0
        self._e_shoff = self._e_phoff + self._e_phentsize * self._e_phnum
        self._e_shstrndx = None
        self._strtab_text = b'\x00'

        self.add_section(self.Section(
            name=None,
            address=0,
            type=self._structs.Elf_SectionType.SHT_NULL,
            flags=0,
            contents=b'',
            size=0))

    def _add_string_section(self):
        self.add_section(self.Section(
            name='.shstrtab',
            address=0,
            type=self._structs.Elf_SectionType.SHT_STRTAB,
            flags=0,

            # will be filled during build
            size=None,
            contents=None))

        self._e_shstrndx = self._e_shnum - 1

    def set_endianity(self, endianity):
        self._endianity = endianity
        self._structs = ElfStructs(endianity)        

    def add_segment(self, address, flags, size):
        self._e_phnum += 1
        self._e_shoff = self._e_phoff + self._e_phentsize * self._e_phnum

        segment = self.Segment(address=address,
           flags=flags,
           size=size)

        self._segments.append(segment)

    def add_section(self, section):
        self._e_shnum += 1
        self._sections.append(section)

        if section.name is not None:
            self._strtab_text += section.name.encode() + b'\x00'

        # create segment for the section if necessary
        if section.type not in (elf_consts.SHT_PROGBITS, ):
            return

        found_matching_segment = False
        for segment in self._segments:
            if (segment.address <= section.address) and (segment.address + len(section.contents) >= section.address):
                found_matching_segment = True

        if not found_matching_segment:
            self.add_segment(section.address, 
                elf_consts.PF_R | elf_consts.PF_W | elf_consts.PF_X, 
                len(section.contents))

    def add_code_section(self, name, address, contents):
        self.add_section(self.Section(
            name=name,
            type=elf_consts.SHT_PROGBITS,
            address=address, 
            contents=contents,
            size=len(contents), 
            flags=elf_consts.SHF_ALLOC | elf_consts.SHF_EXECINSTR))

    def add_empty_data_section(self, name, address, size):
        self.add_section(self.Section(
            name=name,
            type=self._structs.Elf_SectionType.SHT_NOBITS,
            address=address, 
            contents=None, 
            size=size,
            flags=elf_consts.SHF_ALLOC | elf_consts.SHF_WRITE))

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
                'e_shoff': self._e_shoff,
                'e_flags': 0,
                'e_ehsize': self._e_ehsize,
                'e_phentsize': self._e_phentsize,
                'e_phnum': self._e_phnum,
                'e_shentsize': self._e_shentsize,
                'e_shnum': self._e_shnum,
                'e_shstrndx': self._e_shstrndx,
            },
            'segments': [],
            'sections': [],
        }

        # add segments
        segment_data_offset = self._e_shoff + self._e_shentsize * self._e_shnum

        for segment in self._segments:
            elf['segments'].append({
                'p_type': elf_consts.PT_LOAD,
                'p_offset': segment_data_offset,
                'p_vaddr': segment.address,
                'p_paddr': segment.address,
                'p_filesz': segment.size,
                'p_memsz': segment.size,
                'p_flags': segment.flags,
                'p_align': 0x20,
            })
            segment_data_offset += segment.size

        # add sections
        section_data_offset = self._e_shoff + self._e_shentsize * self._e_shnum

        for section in self._sections:
            if section.name is None:
                sh_name = 0
            else:
                sh_name = self._strtab_text.find(section.name.encode() + b'\x00')

            if section.type == self._structs.Elf_SectionType.SHT_STRTAB:
                contents = self._strtab_text
                size = len(contents)
            else:
                contents = section.contents
                size = section.size

            if contents is None:
                contents = b''

            elf['sections'].append({
                'sh_name': sh_name,
                'sh_type': section.type,
                'sh_flags': section.flags,
                'sh_addr': section.address,
                'sh_offset': section_data_offset,
                'sh_size': size,
                'sh_link': 0,
                'sh_info': 0,
                'sh_addralign': 0x20,
                'sh_entsize': 0,
                'data': contents
            })

            section_data_offset += len(contents)

        return structs.Elf32.build(elf)

