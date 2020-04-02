# Introduction
ELF file is not only an executable, but a very convenient way to describe 
a program's layout in memory. The original intention of this project is to 
allow an individual to create an ELF file which describes the memory mapping
used for an embedded program. Especially useful for firmware unpackers, such as:
IDA/Ghidra/etc... They can have all its desired information without the need to
open just an ordinary `.bin` file and running several IDAPython scripts.

# Requirements
The easiest way to manage the requirements for this project is using `poetry`.
If you don't already have it installed, run:

```bash
curl -sSL https://raw.githubusercontent.com/python-poetry/poetry/master/get-poetry.py | python
```

Then inside the directory of this project, run

```bash
poetry install
```

# Running

Now you can just import simpleelf and start playing with it.

## Parsing

Parsing is easy using `ElfStruct`.
Try it out:

```python
from simpleelf.elf_structs import ElfStructs

elf_structs.Elf32.parse(elf_buffer) # outputs a constucts' container
```

## Building from scratch

Building is easy using `ElfBuilder`.
Try it out:

```python
from simpleelf.elf_builder import ElfBuilder
from simpleelf import elf_consts

e = ElfBuilder()
e.set_endianity('>')

# will create a segment containing the section if not currently exists
text_start = 0x1234
text_buffer = b'cybercyberbitimbitim'
e.add_code_section('.text', text_start, text_buffer)

# will create a NOTBITS section
data_address = 0x5678
data_size = 0x200
e.add_empty_data_section('.data', data_address, data_size)

# set entry point
e.set_entry(text_start)

# set machine type
e.set_machine(elf_consts.EM_PPC)

# adding just some additional segment. not assining a section to it.
e.add_segment(0xff000000, 
    elf_consts.PF_R | elf_consts.PF_W | elf_consts.PF_X, 
    0x2000)

# outputs a buffer of the desired ELF file
e.build() 
```
