import "pe"
rule LZEXE_v091_v100a_1_additional: PEiD
{
    strings:
        $a = { 06 0E 1F 8B ?? ?? ?? 8B F1 4E 89 F7 }
    condition:
        $a at pe.entry_point

}