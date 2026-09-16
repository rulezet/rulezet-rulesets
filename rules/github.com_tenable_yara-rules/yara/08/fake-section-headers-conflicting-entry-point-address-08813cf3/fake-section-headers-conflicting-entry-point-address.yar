import "elf"
rule fake_section_headers_conflicting_entry_point_address
{
    meta:
        description = "A fake sections header has been added to the binary."
        family = "Obfuscation"
        filetype = "ELF"
        hash = "a2301180df014f216d34cec8a6a6549638925ae21995779c2d7d2827256a8447"

    condition:
        elf.type == elf.ET_EXEC and
        elf.entry_point < filesize and         elf.number_of_segments > 0 and
        elf.number_of_sections > 0 and
        not
        (
            for any i in (0..elf.number_of_segments):
            (
                (elf.segments[i].offset <= elf.entry_point) and
                ((elf.segments[i].offset + elf.segments[i].file_size) >= elf.entry_point) and
                for any j in (0..elf.number_of_sections):
                (
                    elf.sections[j].offset <= elf.entry_point and
                    ((elf.sections[j].offset + elf.sections[j].size) >= elf.entry_point) and
                    (elf.segments[i].virtual_address + (elf.entry_point - elf.segments[i].offset)) ==
                    (elf.sections[j].address + (elf.entry_point - elf.sections[j].offset))
                )
            )
        )
}