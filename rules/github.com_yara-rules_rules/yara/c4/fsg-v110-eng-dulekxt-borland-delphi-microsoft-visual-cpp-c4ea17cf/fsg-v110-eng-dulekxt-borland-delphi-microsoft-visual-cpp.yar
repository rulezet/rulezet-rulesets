import "pe"
rule FSG_v110_Eng_dulekxt_Borland_Delphi_Microsoft_Visual_Cpp_: PEiD
{
    strings:
        $a = { C1 C8 10 EB 01 0F BF 03 74 66 77 C1 E9 1D 68 83 ?? ?? 77 EB 02 CD 20 5E EB 02 CD 20 2B F7 }
    condition:
        $a at pe.entry_point

}