import "pe"
rule FSG_v110_Eng_dulekxt_Microsoft_Visual_Cpp_60_70_ASM_additional: PEiD
{
    strings:
        $a = { E8 01 00 00 00 0E 59 E8 01 00 00 00 58 58 BE 80 ?? ?? 00 EB 02 61 E9 68 F4 00 00 00 C1 C8 }
    condition:
        $a at pe.entry_point

}