import "pe"
rule FSG_v110_Eng_dulekxt_Borland_Delphi_Microsoft_Visual_Cppx: PEiD
{
    strings:
        $a = { 1B DB E8 02 00 00 00 1A 0D 5B 68 80 ?? ?? 00 E8 01 00 00 00 EA 5A 58 EB 02 CD 20 68 F4 00 }
    condition:
        $a at pe.entry_point

}