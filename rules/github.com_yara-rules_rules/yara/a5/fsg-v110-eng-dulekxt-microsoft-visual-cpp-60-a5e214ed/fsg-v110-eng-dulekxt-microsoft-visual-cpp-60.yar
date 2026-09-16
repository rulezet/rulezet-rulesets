import "pe"
rule FSG_v110_Eng_dulekxt_Microsoft_Visual_Cpp_60_: PEiD
{
    strings:
        $a = { 91 EB 02 CD 20 BF 50 BC 04 6F 91 BE D0 ?? ?? 6F EB 02 CD 20 2B F7 EB 02 F0 46 8D 1D F4 00 }
    condition:
        $a at pe.entry_point

}