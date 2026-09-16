import "pe"
rule FSG_v110_Eng_dulekxt_Borland_Delphi_Microsoft_Visual_Cpp_ASM_: PEiD
{
    strings:
        $a = { EB 02 CD 20 EB 02 CD 20 EB 02 CD 20 C1 E6 18 BB 80 ?? ?? 00 EB 02 82 B8 EB 01 10 8D 05 F4 }
    condition:
        $a at pe.entry_point

}