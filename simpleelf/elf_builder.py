from collections import namedtuple
from typing import Optional, Tuple, Union

from construct import Padding

from simpleelf import elf_consts
from simpleelf.elf_consts import ELFCLASS32
from simpleelf.elf_structs import ElfStructs

Segment = namedtuple('Segment', ['address', 'flags', 'contents'])
Section = namedtuple('Section', ['type', 'name', 'address', 'flags', 'size'])


class ElfBuilder:

    def __init__(self, elf_class: int = ELFCLASS32):
        self._class = elf_class
        self._segments = []
        self._sections = []
        self._e_type = elf_consts.ET_EXEC
        self._machine = 0
        self._entry = 0
        self._endianity = '<'
        self._structs = ElfStructs(self._endianity)
        if elf_class == ELFCLASS32:
            self._e_ehsize = self._structs.Elf32_Ehdr.sizeof()
            self._e_phoff = self._e_ehsize
            self._e_phentsize = 0x20  # TODO: calculate according to the struct
            self._e_shentsize = 0x28  # TODO: calculate according to the struct
        else:
            self._e_ehsize = self._structs.Elf64_Ehdr.sizeof()
            self._e_phoff = self._e_ehsize
            self._e_phentsize = 0x38  # TODO: calculate according to the struct
            self._e_shentsize = 0x40  # TODO: calculate according to the struct
        self._e_phnum = 0
        self._e_shnum = 0
        self._e_shoff = self._e_phoff + self._e_phentsize * self._e_phnum
        self._strtab_text = b'\x00.strtab\x00'

        self._add_section(self._structs.Elf_SectionType.SHT_NULL, 0, 0, 0, 0)

    def set_endianity(self, endianity: str) -> None:
        """
        Set endianity

        :param endianity: Either '<' for LE or '>' for BE
        :return: None
        """
        self._endianity = endianity
        self._structs = ElfStructs(endianity)

    def add_segment(self, address: int, contents: bytes, flags: int) -> None:
        self._e_phnum += 1
        self._e_shoff += self._e_phentsize + len(contents)
        self._segments.append(Segment(address=address, flags=flags, contents=contents))

    def find_loaded_data(self, address: int, size: Optional[int] = None) -> Optional[Tuple[int, bytes]]:
        """
        Searches the entire ELF memory layout for the data loaded at a given address

        :param address: Address to search for
        :param size: Size of data to read from that address
        :return: None of address isn't mapped or a tuple of the offset within the ELF file and the actual data
        """
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

    def add_code_section(self, address: int, size: int, writeable: bool = False,
                         name: Optional[Union[str, int]] = None) -> None:
        """
        Add code section

        :param address: Section address
        :param size: Section size
        :param writeable: Determine if section is writable
        :param name: Section's name (either None, string name, or an offset from .strtab)
        :return: None
        """
        flags = elf_consts.SHF_ALLOC | elf_consts.SHF_EXECINSTR
        if writeable:
            flags |= elf_consts.SHF_WRITE
        self._add_section(self._structs.Elf_SectionType.SHT_PROGBITS, address, size, flags, name=name)

    def add_empty_data_section(self, address: int, size: int, name: Optional[Union[str, int]] = None) -> None:
        """
        Add an empty data section (usually for .bss)

        :param address: Section's address
        :param size: Section's size
        :param name: Section's name (either None, string name, or an offset from .strtab)
        :return:
        """
        self._add_section(self._structs.Elf_SectionType.SHT_NOBITS, address, size,
                          elf_consts.SHF_ALLOC | elf_consts.SHF_WRITE, name=name)

    def set_machine(self, machine: int) -> None:
        """ Set machine type """
        self._machine = machine

    def set_entry(self, entry: int) -> None:
        """ Set entrypoint address """
        self._entry = entry

    def set_type(self, e_type: int) -> None:
        self._e_type = e_type

    def build(self) -> bytes:
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
                    'class': self._class,
                    'data': e_ident_data,
                    'osabi': elf_consts.ELFOSABI_NONE,
                    'pad': Padding(8),
                },
                'e_type': self._e_type,
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

        return structs.Elf32.build(elf) if self._class == ELFCLASS32 else structs.Elf64.build(elf)

    def _add_section(self, type_, address: int, size: int, flags: int, name: Optional[Union[str, int]] = None) -> None:
        """
        Add section

        :param type_: A value from Elf_SectionType enum
        :param address: Section's address
        :param size: Section's size
        :param flags: Section's flags
        :param name: Section's name (either None, string name, or an offset from .strtab)
        :return: None
        """
        if name is not None:
            if isinstance(name, str):
                self._strtab_text += name.encode() + b'\x00'

        # create segment for the section if necessary
        if type_ in (self._structs.Elf_SectionType.SHT_PROGBITS,):
            if self.find_loaded_data(address) is None:
                raise Exception(
                    "section of type SHT_PROGBITS not inside any segment")

        section = Section(
            name=name,
            type=type_,
            address=address,
            size=size,
            flags=flags)

        self._e_shnum += 1
        self._sections.append(section)

    def _add_string_section(self) -> None:
        """ Add string section (.strtab) """
        self._add_section(self._structs.Elf_SectionType.SHT_STRTAB, 0, len(self._strtab_text), 1, elf_consts.SHF_ALLOC)
