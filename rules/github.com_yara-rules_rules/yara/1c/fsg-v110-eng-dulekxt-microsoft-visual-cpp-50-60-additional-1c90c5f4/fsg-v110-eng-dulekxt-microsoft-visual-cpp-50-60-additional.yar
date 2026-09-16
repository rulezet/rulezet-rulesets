import "pe"
rule FSG_v110_Eng_dulekxt_Microsoft_Visual_Cpp_50_60_additional: PEiD
{
    strings:
        $a = { 8D 50 12 2B C9 B1 1E 8A 02 34 77 88 02 42 E2 F7 C8 8C }
    condition:
        $a at pe.entry_point

}