import "pe"
rule FSG_v110_Eng_dulekxt_Microsoft_Visual_Cpp_60_70_ASM: PEiD
{
    strings:
        $a = { E8 01 00 00 00 5A 5E E8 02 00 00 00 BA DD 5E 03 F2 EB 01 64 BB 80 ?? ?? 00 8B FA EB 01 A8 }
    condition:
        $a at pe.entry_point

}