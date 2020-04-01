from collections import namedtuple

from construct import *


class Structs:
    EI_NIDENT = 16
    ELFMAG = b"\177ELF"

    PF_R = 0x4
    PF_W = 0x2
    PF_X = 0x1

    SHF_WRITE = 0x1
    SHF_ALLOC = 0x2
    SHF_EXECINSTR = 0x4
    SHF_RELA_LIVEPATCH = 0x00100000
    SHF_RO_AFTER_INIT = 0x00200000
    SHF_MASKPROC = 0xf0000000

    def __init__(self, endianity='<'):
        if endianity == '<':
            Int8u = Int8ul
            Int16u = Int16ul
            Int32u = Int32ul
        else:
            Int8u = Int8ub
            Int16u = Int16ub
            Int32u = Int32ub

        self.Elf_Class = Enum(Hex(Int8u),
                              ELFCLASSNONE=0,
                              ELFCLASS32=1,
                              ELFCLASS64=2,
                              ELFCLASSNUM=3,
                              )

        self.Elf_Data = Enum(Hex(Int8u),
                             ELFDATANONE=0,
                             ELFDATA2LSB=1,
                             ELFDATA2MSB=2,
                             )

        self.Elf_SegmentType = Enum(Hex(Int32u),
                                    PT_NULL=0,
                                    PT_LOAD=1,
                                    PT_DYNAMIC=2,
                                    PT_INTER=3,
                                    PT_NOTE=4,
                                    PT_SHLIB=5,
                                    PT_PHDR=6,
                                    PT_TLS=7,  # Thread local storage segment
                                    PT_LOOS=0x60000000,  # OS-specific
                                    PT_HIOS=0x6fffffff,  # OS-specific
                                    PT_LOPROC=0x70000000,
                                    PT_HIPROC=0x7fffffff,
                                    PT_GNU_EH_FRAME=0x6474e550,
                                    )

        self.Elf_Type = Enum(Hex(Int16u),
                             ET_NONE=0,
                             ET_REL=1,
                             ET_EXEC=2,
                             ET_DYN=3,
                             ET_CORE=4,
                             ET_LOPROC=0xff00,
                             ET_HIPROC=0xffff,
                             )

        self.Elf_Version = Enum(Hex(Int8u),
                        EV_NONE=0,
                        EV_CURRENT=1,
                        EV_NUM=2,
                        )

        self.Elf_Version2 = Enum(Hex(Int32u),
                                EV_NONE=0,
                                EV_CURRENT=1,
                                EV_NUM=2,
                                )

        self.Elf_OsAbi = Enum(Hex(Int8u),
                              ELFOSABI_NONE=0,
                              ELFOSABI_LINUX=3,
                              )

        self.Elf32_Phdr = Struct(
            'p_type' / self.Elf_SegmentType,
            'p_offset' / Hex(Int32u),
            'p_vaddr' / Hex(Int32u),
            'p_paddr' / Hex(Int32u),
            'p_filesz' / Hex(Int32u),
            'p_memsz' / Hex(Int32u),
            'p_flags' / Hex(Int32u),
            'p_align' / Hex(Int32u),
        )

        self.Elf32_Ehdr = Struct(
            'e_ident' / Struct(
                'magic' / Const(self.ELFMAG),
                'class' / self.Elf_Class,
                'data' / self.Elf_Data,
                'version' / Default(self.Elf_Version, self.Elf_Version.EV_CURRENT),
                'osabi' / self.Elf_OsAbi,
                'pad' / Padding(8),
                ),
        'e_type' / Default(self.Elf_Type, self.Elf_Type.ET_EXEC),
        'e_machine' / Hex(Int16u),
        'e_version' / Default(self.Elf_Version2, self.Elf_Version2.EV_CURRENT),
        'e_entry' / Hex(Int32u),
        'e_phoff' / Hex(Int32u),
        'e_shoff' / Hex(Int32u),
        'e_flags' / Default(Hex(Int32u), 0),
        'e_ehsize' / Hex(Int16u),
        'e_phentsize' / Hex(Int16u),
        'e_phnum' / Hex(Int16u),
        'e_shentsize' / Hex(Int16u),
        'e_shnum' / Hex(Int16u),
        'e_shstrndx' / Hex(Int16u),
        )

        # special section indexes 
        self.Elf_SectionIndex = Enum(Hex(Int32u),
                                     SHN_UNDEF=0,
                                     SHN_LORESERVE=0xff00,
                                     SHN_LOPROC=0xff00,
                                     SHN_HIPROC=0xff1f,
                                     SHN_LIVEPATCH=0xff20,
                                     SHN_ABS=0xfff1,
                                     SHN_COMMON=0xfff2,
                                     SHN_HIRESERVE=0xffff,
                                     )

        self.Elf_SectionType = Enum(Hex(Int32u),
                                    SHT_NULL=0,
                                    SHT_PROGBITS=1,
                                    SHT_SYMTAB=2,
                                    SHT_STRTAB=3,
                                    SHT_RELA=4,
                                    SHT_HASH=5,
                                    SHT_DYNAMIC=6,
                                    SHT_NOTE=7,
                                    SHT_NOBITS=8,
                                    SHT_REL=9,
                                    SHT_SHLIB=10,
                                    SHT_DYNSYM=11,
                                    SHT_NUM=12,
                                    SHT_LOPROC=0x70000000,
                                    SHT_HIPROC=0x7fffffff,
                                    SHT_LOUSER=0x80000000,
                                    SHT_HIUSER=0xffffffff,
                                    )

        self.Elf32_Shdr = Struct(
            'sh_name' / self.Elf_SectionIndex,
            'sh_type' / self.Elf_SectionType,
            'sh_flags' / Hex(Int32u),
            'sh_addr' / Hex(Int32u),
            'sh_offset' / Hex(Int32u),
            'sh_size' / Hex(Int32u),
            'sh_link' / Hex(Int32u),
            'sh_info' / Hex(Int32u),
            'sh_addralign' / Hex(Int32u),
            'sh_entsize' / Hex(Int32u),
            'data' / If(this.sh_type != self.Elf_SectionType.SHT_NOBITS,
                Pointer(this.sh_offset, Bytes(this.sh_size)))
        )

        self.Elf32 = Struct(
            'header' / self.Elf32_Ehdr,
            'segments' / Pointer(this.header.e_phoff, Array(this.header.e_phnum, self.Elf32_Phdr)),
            'sections' / Pointer(this.header.e_shoff, Array(this.header.e_shnum, self.Elf32_Shdr)),
        )


class ElfBuilder:
    Segment = namedtuple('Segment', ['address', 'flags', 'size'])
    Section = namedtuple('Section', ['type', 'name', 'address', 'contents', 'flags', 'size'])

    def __init__(self):
        self._segments = []
        self._sections = []
        self._machine = 0
        self._entry = 0
        self._endianity = '<'
        self._structs = Structs(self._endianity)
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
        self._structs = Structs(endianity)        

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
        if section.type not in (self._structs.Elf_SectionType.SHT_PROGBITS):
            return

        found_matching_segment = False
        for segment in self._segments:
            if (segment.address <= section.address) and (segment.address + len(section.contents) >= section.address):
                found_matching_segment = True

        if not found_matching_segment:
            self.add_segment(section.address, 
                self._structs.PF_R | self._structs.PF_W | self._structs.PF_X, 
                len(section.contents))

    def add_code_section(self, name, address, contents):
        self.add_section(self.Section(
            name=name,
            type=self._structs.Elf_SectionType.SHT_PROGBITS,
            address=address, 
            contents=contents,
            size=len(contents), 
            flags=self._structs.SHF_ALLOC | self._structs.SHF_EXECINSTR))

    def add_empty_data_section(self, name, address, size):
        self.add_section(self.Section(
            name=name,
            type=self._structs.Elf_SectionType.SHT_NOBITS,
            address=address, 
            contents=None, 
            size=size,
            flags=self._structs.SHF_ALLOC | self._structs.SHF_WRITE))

    def set_machine(self, machine):
        self._machine = machine

    def set_entry(self, entry):
        self._entry = entry

    def build(self):
        structs = self._structs

        # append strtab as the last section
        self._add_string_section()

        if self._endianity == '<':
            e_ident_data = structs.Elf_Data.ELFDATA2LSB
        else:
            e_ident_data = structs.Elf_Data.ELFDATA2MSB

        elf = {
            'header': {
                'e_ident': {
                    'magic': structs.ELFMAG,
                    'class': structs.Elf_Class.ELFCLASS32,
                    'data': e_ident_data,
                    'osabi': structs.Elf_OsAbi.ELFOSABI_NONE,
                    'pad': Padding(8),
                },
                'e_type': structs.Elf_Type.ET_EXEC,
                'e_machine': self._machine,
                'e_version': structs.Elf_Version.EV_CURRENT,
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
                'p_type': self._structs.Elf_SegmentType.PT_LOAD,
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

