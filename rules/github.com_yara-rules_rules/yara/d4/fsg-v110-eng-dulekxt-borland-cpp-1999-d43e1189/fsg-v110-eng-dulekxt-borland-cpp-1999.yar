import "pe"
rule FSG_v110_Eng_dulekxt_Borland_Cpp_1999: PEiD
{
    strings:
        $a = { EB 02 CD 20 2B C8 68 80 ?? ?? 00 EB 02 1E BB 5E EB 02 CD 20 68 B1 2B 6E 37 40 5B 0F B6 C9 }
    condition:
        $a at pe.entry_point

}