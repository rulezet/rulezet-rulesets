import "elf"
rule single_load_rwe
{
    meta:
        description = "Flags binaries with a single LOAD segment marked as RWE."
        family = "Stager"
        filetype = "ELF"
        hash = "711a06265c71a7157ef1732c56e02a992e56e9d9383ca0f6d98cd96a30e37299"

    condition:
        elf.number_of_segments == 1 and
        elf.segments[0].type == elf.PT_LOAD and
        elf.segments[0].flags == elf.PF_R | elf.PF_W | elf.PF_X
}