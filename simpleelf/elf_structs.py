from construct import Array, Bytes, Const, Default, Enum, Hex, If, Int8ub, Int8ul, Int16ub, Int16ul, Int32ub, Int32ul, \
    Int64ub, Int64ul, Padding, Pointer, Struct, this

from simpleelf import elf_consts


class ElfStructs:
    def __init__(self, endianity='<'):
        if endianity == '<':
            Int8u = Int8ul
            Int16u = Int16ul
            # Int32s = Int32sl
            Int32u = Int32ul
            # Int64s = Int64sl
            Int64u = Int64ul
        else:
            Int8u = Int8ub
            Int16u = Int16ub
            # Int32s = Int32sb
            Int32u = Int32ub
            # Int64s = Int64sb
            Int64u = Int64ub

        Elf32_Addr = Int32u
        # Elf32_Half = Int16u
        Elf32_Off = Int32u
        # Elf32_Sword = Int32s
        Elf32_Word = Int32u

        Elf64_Addr = Int64u
        # Elf64_Half = Int16u
        # Elf64_SHalf = Int16u
        Elf64_Off = Int64u
        # Elf64_Sword = Int32s
        Elf64_Word = Int32u
        Elf64_Xword = Int64u
        # Elf64_Sxword = Int64s

        self.Elf_Class = Enum(Hex(Int8u),
                              ELFCLASSNONE=elf_consts.ELFCLASSNONE,
                              ELFCLASS32=elf_consts.ELFCLASS32,
                              ELFCLASS64=elf_consts.ELFCLASS64,
                              ELFCLASSNUM=elf_consts.ELFCLASSNUM,
                              )

        self.Elf_Data = Enum(Hex(Int8u),
                             ELFDATANONE=elf_consts.ELFDATANONE,
                             ELFDATA2LSB=elf_consts.ELFDATA2LSB,
                             ELFDATA2MSB=elf_consts.ELFDATA2MSB,
                             )

        self.Elf_Machine = Enum(Int16u,
                                EM_NONE=elf_consts.EM_NONE,
                                EM_M32=elf_consts.EM_M32,
                                EM_SPARC=elf_consts.EM_SPARC,
                                EM_386=elf_consts.EM_386,
                                EM_68K=elf_consts.EM_68K,
                                EM_88K=elf_consts.EM_88K,
                                EM_IAMCU=elf_consts.EM_IAMCU,
                                EM_860=elf_consts.EM_860,
                                EM_MIPS=elf_consts.EM_MIPS,
                                EM_S370=elf_consts.EM_S370,
                                EM_MIPS_RS3_LE=elf_consts.EM_MIPS_RS3_LE,
                                EM_PARISC=elf_consts.EM_PARISC,
                                EM_VPP500=elf_consts.EM_VPP500,
                                EM_SPARC32PLUS=elf_consts.EM_SPARC32PLUS,
                                EM_960=elf_consts.EM_960,
                                EM_PPC=elf_consts.EM_PPC,
                                EM_PPC64=elf_consts.EM_PPC64,
                                EM_S390=elf_consts.EM_S390,
                                EM_SPU=elf_consts.EM_SPU,
                                EM_V800=elf_consts.EM_V800,
                                EM_FR20=elf_consts.EM_FR20,
                                EM_RH32=elf_consts.EM_RH32,
                                EM_RCE=elf_consts.EM_RCE,
                                EM_ARM=elf_consts.EM_ARM,
                                EM_ALPHA=elf_consts.EM_ALPHA,
                                EM_SH=elf_consts.EM_SH,
                                EM_SPARCV9=elf_consts.EM_SPARCV9,
                                EM_TRICORE=elf_consts.EM_TRICORE,
                                EM_ARC=elf_consts.EM_ARC,
                                EM_H8_300=elf_consts.EM_H8_300,
                                EM_H8_300H=elf_consts.EM_H8_300H,
                                EM_H8S=elf_consts.EM_H8S,
                                EM_H8_500=elf_consts.EM_H8_500,
                                EM_IA_64=elf_consts.EM_IA_64,
                                EM_MIPS_X=elf_consts.EM_MIPS_X,
                                EM_COLDFIRE=elf_consts.EM_COLDFIRE,
                                EM_68HC12=elf_consts.EM_68HC12,
                                EM_MMA=elf_consts.EM_MMA,
                                EM_PCP=elf_consts.EM_PCP,
                                EM_NCPU=elf_consts.EM_NCPU,
                                EM_NDR1=elf_consts.EM_NDR1,
                                EM_STARCORE=elf_consts.EM_STARCORE,
                                EM_ME16=elf_consts.EM_ME16,
                                EM_ST100=elf_consts.EM_ST100,
                                EM_TINYJ=elf_consts.EM_TINYJ,
                                EM_X86_64=elf_consts.EM_X86_64,
                                EM_PDSP=elf_consts.EM_PDSP,
                                EM_PDP10=elf_consts.EM_PDP10,
                                EM_PDP11=elf_consts.EM_PDP11,
                                EM_FX66=elf_consts.EM_FX66,
                                EM_ST9PLUS=elf_consts.EM_ST9PLUS,
                                EM_ST7=elf_consts.EM_ST7,
                                EM_68HC16=elf_consts.EM_68HC16,
                                EM_68HC11=elf_consts.EM_68HC11,
                                EM_68HC08=elf_consts.EM_68HC08,
                                EM_68HC05=elf_consts.EM_68HC05,
                                EM_SVX=elf_consts.EM_SVX,
                                EM_ST19=elf_consts.EM_ST19,
                                EM_VAX=elf_consts.EM_VAX,
                                EM_CRIS=elf_consts.EM_CRIS,
                                EM_JAVELIN=elf_consts.EM_JAVELIN,
                                EM_FIREPATH=elf_consts.EM_FIREPATH,
                                EM_ZSP=elf_consts.EM_ZSP,
                                EM_MMIX=elf_consts.EM_MMIX,
                                EM_HUANY=elf_consts.EM_HUANY,
                                EM_PRISM=elf_consts.EM_PRISM,
                                EM_AVR=elf_consts.EM_AVR,
                                EM_FR30=elf_consts.EM_FR30,
                                EM_D10V=elf_consts.EM_D10V,
                                EM_D30V=elf_consts.EM_D30V,
                                EM_V850=elf_consts.EM_V850,
                                EM_M32R=elf_consts.EM_M32R,
                                EM_MN10300=elf_consts.EM_MN10300,
                                EM_MN10200=elf_consts.EM_MN10200,
                                EM_PJ=elf_consts.EM_PJ,
                                EM_OPENRISC=elf_consts.EM_OPENRISC,
                                EM_ARC_COMPACT=elf_consts.EM_ARC_COMPACT,
                                EM_XTENSA=elf_consts.EM_XTENSA,
                                EM_VIDEOCORE=elf_consts.EM_VIDEOCORE,
                                EM_TMM_GPP=elf_consts.EM_TMM_GPP,
                                EM_NS32K=elf_consts.EM_NS32K,
                                EM_TPC=elf_consts.EM_TPC,
                                EM_SNP1K=elf_consts.EM_SNP1K,
                                EM_ST200=elf_consts.EM_ST200,
                                EM_IP2K=elf_consts.EM_IP2K,
                                EM_MAX=elf_consts.EM_MAX,
                                EM_CR=elf_consts.EM_CR,
                                EM_F2MC16=elf_consts.EM_F2MC16,
                                EM_MSP430=elf_consts.EM_MSP430,
                                EM_BLACKFIN=elf_consts.EM_BLACKFIN,
                                EM_SE_C33=elf_consts.EM_SE_C33,
                                EM_SEP=elf_consts.EM_SEP,
                                EM_ARCA=elf_consts.EM_ARCA,
                                EM_UNICORE=elf_consts.EM_UNICORE,
                                EM_EXCESS=elf_consts.EM_EXCESS,
                                EM_DXP=elf_consts.EM_DXP,
                                EM_ALTERA_NIOS2=elf_consts.EM_ALTERA_NIOS2,
                                EM_CRX=elf_consts.EM_CRX,
                                EM_XGATE=elf_consts.EM_XGATE,
                                EM_C166=elf_consts.EM_C166,
                                EM_M16C=elf_consts.EM_M16C,
                                EM_DSPIC30F=elf_consts.EM_DSPIC30F,
                                EM_CE=elf_consts.EM_CE,
                                EM_M32C=elf_consts.EM_M32C,
                                EM_TSK3000=elf_consts.EM_TSK3000,
                                EM_RS08=elf_consts.EM_RS08,
                                EM_SHARC=elf_consts.EM_SHARC,
                                EM_ECOG2=elf_consts.EM_ECOG2,
                                EM_SCORE7=elf_consts.EM_SCORE7,
                                EM_DSP24=elf_consts.EM_DSP24,
                                EM_VIDEOCORE3=elf_consts.EM_VIDEOCORE3,
                                EM_LATTICEMICO32=elf_consts.EM_LATTICEMICO32,
                                EM_SE_C17=elf_consts.EM_SE_C17,
                                EM_TI_C6000=elf_consts.EM_TI_C6000,
                                EM_TI_C2000=elf_consts.EM_TI_C2000,
                                EM_TI_C5500=elf_consts.EM_TI_C5500,
                                EM_TI_ARP32=elf_consts.EM_TI_ARP32,
                                EM_TI_PRU=elf_consts.EM_TI_PRU,
                                EM_MMDSP_PLUS=elf_consts.EM_MMDSP_PLUS,
                                EM_CYPRESS_M8C=elf_consts.EM_CYPRESS_M8C,
                                EM_R32C=elf_consts.EM_R32C,
                                EM_TRIMEDIA=elf_consts.EM_TRIMEDIA,
                                EM_QDSP6=elf_consts.EM_QDSP6,
                                EM_8051=elf_consts.EM_8051,
                                EM_STXP7X=elf_consts.EM_STXP7X,
                                EM_NDS32=elf_consts.EM_NDS32,
                                EM_ECOG1=elf_consts.EM_ECOG1,
                                EM_ECOG1X=elf_consts.EM_ECOG1X,
                                EM_MAXQ30=elf_consts.EM_MAXQ30,
                                EM_XIMO16=elf_consts.EM_XIMO16,
                                EM_MANIK=elf_consts.EM_MANIK,
                                EM_CRAYNV2=elf_consts.EM_CRAYNV2,
                                EM_RX=elf_consts.EM_RX,
                                EM_METAG=elf_consts.EM_METAG,
                                EM_MCST_ELBRUS=elf_consts.EM_MCST_ELBRUS,
                                EM_ECOG16=elf_consts.EM_ECOG16,
                                EM_CR16=elf_consts.EM_CR16,
                                EM_ETPU=elf_consts.EM_ETPU,
                                EM_SLE9X=elf_consts.EM_SLE9X,
                                EM_L10M=elf_consts.EM_L10M,
                                EM_K10M=elf_consts.EM_K10M,
                                EM_AVR32=elf_consts.EM_AVR32,
                                EM_STM8=elf_consts.EM_STM8,
                                EM_TILE64=elf_consts.EM_TILE64,
                                EM_TILEPRO=elf_consts.EM_TILEPRO,
                                EM_MICROBLAZE=elf_consts.EM_MICROBLAZE,
                                EM_CUDA=elf_consts.EM_CUDA,
                                EM_TILEGX=elf_consts.EM_TILEGX,
                                EM_CLOUDSHIELD=elf_consts.EM_CLOUDSHIELD,
                                EM_COREA_1ST=elf_consts.EM_COREA_1ST,
                                EM_COREA_2ND=elf_consts.EM_COREA_2ND,
                                EM_ARC_COMPACT2=elf_consts.EM_ARC_COMPACT2,
                                EM_OPEN8=elf_consts.EM_OPEN8,
                                EM_RL78=elf_consts.EM_RL78,
                                EM_VIDEOCORE5=elf_consts.EM_VIDEOCORE5,
                                EM_78KOR=elf_consts.EM_78KOR,
                                EM_56800EX=elf_consts.EM_56800EX,
                                EM_BA1=elf_consts.EM_BA1,
                                EM_BA2=elf_consts.EM_BA2,
                                EM_XCORE=elf_consts.EM_XCORE,
                                EM_MCHP_PIC=elf_consts.EM_MCHP_PIC,
                                EM_INTEL205=elf_consts.EM_INTEL205,
                                EM_INTEL206=elf_consts.EM_INTEL206,
                                EM_INTEL207=elf_consts.EM_INTEL207,
                                EM_INTEL208=elf_consts.EM_INTEL208,
                                EM_INTEL209=elf_consts.EM_INTEL209,
                                EM_KM32=elf_consts.EM_KM32,
                                EM_KMX32=elf_consts.EM_KMX32,
                                EM_KMX16=elf_consts.EM_KMX16,
                                EM_KMX8=elf_consts.EM_KMX8,
                                EM_KVARC=elf_consts.EM_KVARC,
                                EM_CDP=elf_consts.EM_CDP,
                                EM_COGE=elf_consts.EM_COGE,
                                EM_COOL=elf_consts.EM_COOL,
                                EM_NORC=elf_consts.EM_NORC,
                                EM_CSR_KALIMBA=elf_consts.EM_CSR_KALIMBA,
                                EM_Z80=elf_consts.EM_Z80,
                                EM_VISIUM=elf_consts.EM_VISIUM,
                                EM_FT32=elf_consts.EM_FT32,
                                EM_MOXIE=elf_consts.EM_MOXIE,
                                EM_AMDGPU=elf_consts.EM_AMDGPU,
                                EM_RISCV=elf_consts.EM_RISCV,
                                )

        self.Elf_SegmentType = Enum(Hex(Int32u),
                                    PT_NULL=elf_consts.PT_NULL,
                                    PT_LOAD=elf_consts.PT_LOAD,
                                    PT_DYNAMIC=elf_consts.PT_DYNAMIC,
                                    PT_INTER=elf_consts.PT_INTER,
                                    PT_NOTE=elf_consts.PT_NOTE,
                                    PT_SHLIB=elf_consts.PT_SHLIB,
                                    PT_PHDR=elf_consts.PT_PHDR,
                                    PT_TLS=elf_consts.PT_TLS,
                                    PT_LOOS=elf_consts.PT_LOOS,
                                    PT_HIOS=elf_consts.PT_HIOS,
                                    PT_LOPROC=elf_consts.PT_LOPROC,
                                    PT_HIPROC=elf_consts.PT_HIPROC,
                                    PT_GNU_EH_FRAME=elf_consts.PT_GNU_EH_FRAME,
                                    )

        self.Elf_Type = Enum(Hex(Int16u),
                             ET_NONE=elf_consts.ET_NONE,
                             ET_REL=elf_consts.ET_REL,
                             ET_EXEC=elf_consts.ET_EXEC,
                             ET_DYN=elf_consts.ET_DYN,
                             ET_CORE=elf_consts.ET_CORE,
                             ET_LOPROC=elf_consts.ET_LOPROC,
                             ET_HIPROC=elf_consts.ET_HIPROC,
                             )

        self.Elf_Version = Enum(Hex(Int8u),
                                EV_NONE=elf_consts.EV_NONE,
                                EV_CURRENT=elf_consts.EV_CURRENT,
                                EV_NUM=elf_consts.EV_NUM,
                                )

        self.Elf_Version2 = Enum(Hex(Int32u),
                                 EV_NONE=elf_consts.EV_NONE,
                                 EV_CURRENT=elf_consts.EV_CURRENT,
                                 EV_NUM=elf_consts.EV_NUM,
                                 )

        self.Elf_OsAbi = Enum(Hex(Int8u),
                              ELFOSABI_NONE=elf_consts.ELFOSABI_NONE,
                              ELFOSABI_LINUX=elf_consts.ELFOSABI_LINUX,
                              )

        # special section indexes
        self.Elf_SectionIndex = Enum(Hex(Int32u),
                                     SHN_UNDEF=elf_consts.SHN_UNDEF,
                                     SHN_LORESERVE=elf_consts.SHN_LORESERVE,
                                     SHN_LOPROC=elf_consts.SHN_LOPROC,
                                     SHN_HIPROC=elf_consts.SHN_HIPROC,
                                     SHN_LIVEPATCH=elf_consts.SHN_LIVEPATCH,
                                     SHN_ABS=elf_consts.SHN_ABS,
                                     SHN_COMMON=elf_consts.SHN_COMMON,
                                     SHN_HIRESERVE=elf_consts.SHN_HIRESERVE,
                                     )

        self.Elf_SectionType = Enum(Hex(Int32u),
                                    SHT_NULL=elf_consts.SHT_NULL,
                                    SHT_PROGBITS=elf_consts.SHT_PROGBITS,
                                    SHT_SYMTAB=elf_consts.SHT_SYMTAB,
                                    SHT_STRTAB=elf_consts.SHT_STRTAB,
                                    SHT_RELA=elf_consts.SHT_RELA,
                                    SHT_HASH=elf_consts.SHT_HASH,
                                    SHT_DYNAMIC=elf_consts.SHT_DYNAMIC,
                                    SHT_NOTE=elf_consts.SHT_NOTE,
                                    SHT_NOBITS=elf_consts.SHT_NOBITS,
                                    SHT_REL=elf_consts.SHT_REL,
                                    SHT_SHLIB=elf_consts.SHT_SHLIB,
                                    SHT_DYNSYM=elf_consts.SHT_DYNSYM,
                                    SHT_NUM=elf_consts.SHT_NUM,
                                    SHT_LOPROC=elf_consts.SHT_LOPROC,
                                    SHT_HIPROC=elf_consts.SHT_HIPROC,
                                    SHT_LOUSER=elf_consts.SHT_LOUSER,
                                    SHT_HIUSER=elf_consts.SHT_HIUSER,
                                    )

        self.Elf32_Phdr = Struct(
            'p_type' / self.Elf_SegmentType,
            'p_offset' / Hex(Elf32_Off),
            'p_vaddr' / Hex(Elf32_Addr),
            'p_paddr' / Hex(Elf32_Addr),
            'p_filesz' / Hex(Elf32_Word),
            'p_memsz' / Hex(Elf32_Word),
            'p_flags' / Hex(Elf32_Word),
            'p_align' / Hex(Elf32_Word),
            'data' / If(this.p_type == self.Elf_SegmentType.PT_LOAD,
                        Pointer(this.p_offset, Bytes(this.p_filesz)))
        )

        self.Elf64_Phdr = Struct(
            'p_type' / self.Elf_SegmentType,
            'p_flags' / Hex(Elf64_Word),
            'p_offset' / Hex(Elf64_Off),
            'p_vaddr' / Hex(Elf64_Addr),
            'p_paddr' / Hex(Elf64_Addr),
            'p_filesz' / Hex(Elf64_Xword),
            'p_memsz' / Hex(Elf64_Xword),
            'p_align' / Hex(Elf64_Xword),
            'data' / If(this.p_type == self.Elf_SegmentType.PT_LOAD,
                        Pointer(this.p_offset, Bytes(this.p_filesz)))
        )

        self.Elf32_Ehdr = Struct(
            'e_ident' / Struct(
                'magic' / Const(elf_consts.ELFMAG),
                'class' / self.Elf_Class,
                'data' / self.Elf_Data,
                'version' / Default(self.Elf_Version,
                                    self.Elf_Version.EV_CURRENT),
                'osabi' / self.Elf_OsAbi,
                'pad' / Padding(8),
            ),
            'e_type' / Default(self.Elf_Type, self.Elf_Type.ET_EXEC),
            'e_machine' / Hex(self.Elf_Machine),
            'e_version' / Default(self.Elf_Version2,
                                  self.Elf_Version2.EV_CURRENT),
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

        self.Elf64_Ehdr = Struct(
            'e_ident' / Struct(
                'magic' / Const(elf_consts.ELFMAG),
                'class' / self.Elf_Class,
                'data' / self.Elf_Data,
                'version' / Default(self.Elf_Version,
                                    self.Elf_Version.EV_CURRENT),
                'osabi' / self.Elf_OsAbi,
                'pad' / Padding(8),
            ),
            'e_type' / Default(self.Elf_Type, self.Elf_Type.ET_EXEC),
            'e_machine' / Hex(self.Elf_Machine),
            'e_version' / Default(self.Elf_Version2,
                                  self.Elf_Version2.EV_CURRENT),
            'e_entry' / Hex(Elf64_Addr),
            'e_phoff' / Hex(Elf64_Off),
            'e_shoff' / Hex(Elf64_Off),
            'e_flags' / Default(Hex(Int32u), 0),
            'e_ehsize' / Hex(Int16u),
            'e_phentsize' / Hex(Int16u),
            'e_phnum' / Hex(Int16u),
            'e_shentsize' / Hex(Int16u),
            'e_shnum' / Hex(Int16u),
            'e_shstrndx' / Hex(Int16u),
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

        self.Elf64_Shdr = Struct(
            'sh_name' / self.Elf_SectionIndex,
            'sh_type' / self.Elf_SectionType,
            'sh_flags' / Hex(Elf64_Xword),
            'sh_addr' / Hex(Elf64_Addr),
            'sh_offset' / Hex(Elf64_Off),
            'sh_size' / Hex(Elf64_Xword),
            'sh_link' / Hex(Elf64_Word),
            'sh_info' / Hex(Elf64_Word),
            'sh_addralign' / Hex(Elf64_Xword),
            'sh_entsize' / Hex(Elf64_Xword),
            'data' / If(this.sh_type != self.Elf_SectionType.SHT_NOBITS,
                        Pointer(this.sh_offset, Bytes(this.sh_size)))
        )

        self.Elf32 = Struct(
            'header' / self.Elf32_Ehdr,
            'segments' / Pointer(this.header.e_phoff,
                                 Array(this.header.e_phnum, self.Elf32_Phdr)),
            'sections' / Pointer(this.header.e_shoff,
                                 Array(this.header.e_shnum, self.Elf32_Shdr)),
        )

        self.Elf64 = Struct(
            'header' / self.Elf64_Ehdr,
            'segments' / Pointer(this.header.e_phoff,
                                 Array(this.header.e_phnum, self.Elf64_Phdr)),
            'sections' / Pointer(this.header.e_shoff,
                                 Array(this.header.e_shnum, self.Elf64_Shdr)),
        )
