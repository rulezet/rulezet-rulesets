import "pe"
rule FSG_v110_Eng_dulekxt_Microsoft_Visual_Cpp_50_60: PEiD
{
    strings:
        $a = { 33 D2 0F BE D2 EB 01 C7 EB 01 D8 8D 05 80 ?? ?? ?? EB 02 CD 20 EB 01 F8 BE F4 00 00 00 EB }
    condition:
        $a at pe.entry_point

}