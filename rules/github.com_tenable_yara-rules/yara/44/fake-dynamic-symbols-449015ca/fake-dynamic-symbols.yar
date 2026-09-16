import "elf"
rule fake_dynamic_symbols
{
    meta:
        description = "A fake dynamic symbol table has been added to the binary"
        family = "Obfuscation"
        filetype = "ELF"
        hash = "51676ae7e151a0b906c3a8ad34f474cb5b65eaa3bf40bb09b00c624747bcb241"

    condition:
        elf.type == elf.ET_EXEC and
        elf.entry_point < filesize and         elf.number_of_sections > 0 and
        elf.dynamic_section_entries > 0 and
        for any i in (0..elf.dynamic_section_entries):
        (
            elf.dynamic[i].type == elf.DT_SYMTAB and
            not
            (
                for any j in (0..elf.number_of_sections):
                (
                    elf.sections[j].type == elf.SHT_DYNSYM and
                    for any k in (0..elf.number_of_segments):
                    (
                        (elf.segments[k].virtual_address <= elf.dynamic[i].val) and
                        ((elf.segments[k].virtual_address + elf.segments[k].file_size) >= elf.dynamic[i].val) and
                        (elf.segments[k].offset + (elf.dynamic[i].val - elf.segments[k].virtual_address)) == elf.sections[j].offset
                    )
                )
            )
        )
}