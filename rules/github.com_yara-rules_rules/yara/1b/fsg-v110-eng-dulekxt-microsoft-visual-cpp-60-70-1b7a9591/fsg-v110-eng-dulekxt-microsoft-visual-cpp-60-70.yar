import "pe"
rule FSG_v110_Eng_dulekxt_Microsoft_Visual_Cpp_60_70_: PEiD
{
    strings:
        $a = { 0B D0 8B DA E8 02 00 00 00 40 A0 5A EB 01 9D B8 80 ?? ?? ?? EB 02 CD 20 03 D3 8D 35 F4 00 }
    condition:
        $a at pe.entry_point

}