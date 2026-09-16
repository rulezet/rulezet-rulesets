import "pe"
rule FSG_v110_Eng_dulekxt_Microsoft_Visual_Cpp_4x_LCC_Win32_1x_additional: PEiD
{
    strings:
        $a = { B8 ?? ?? 8E D8 B8 ?? ?? CD 21 A3 ?? ?? 3C 03 7D ?? B4 09 }
    condition:
        $a at pe.entry_point

}