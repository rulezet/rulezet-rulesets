import "pe"
rule LZEXE_v091_v100a_2: PEiD
{
    strings:
        $a = { BF ?? ?? 06 89 F9 0E 41 1F 8C CB 89 FE }
    condition:
        $a at pe.entry_point

}