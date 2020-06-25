# Introduction
ELF file is not only an executable, but a very convenient way to describe 
a program's layout in memory. The original intention of this project is to 
allow an individual to create an ELF file which describes the memory mapping
used for an embedded program. Especially useful for firmware unpackers, such as:
IDA/Ghidra/etc... They can have all its desired information without the need to
open just an ordinary `.bin` file and running several IDAPython scripts
(I'm sick of `Load additional binary file...` option).

Pull Requests are of course more than welcome :smirk:.

# Installation

Support: Python 2.7 and Python 3.x.

Use `pip`:

```bash
python3 -m pip install simpleelf
```

Or from the sources from sources:

```bash
git clone git@github.com:doronz88/simpleelf.git
cd simpleelf
python setup.py install
```

# Running

Now you can just import simpleelf and start playing with it.

## Parsing

Parsing is easy using `ElfStruct`.
Try it out:

```python
from simpleelf.elf_structs import ElfStructs

ElfStructs('<').Elf32.parse(elf_buffer) # outputs a constucts' container
```

## Building from scratch

Building is easy using `ElfBuilder`.
Try it out:

```python
from simpleelf.elf_builder import ElfBuilder
from simpleelf import elf_consts

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

# get raw elf
e.build()
```
