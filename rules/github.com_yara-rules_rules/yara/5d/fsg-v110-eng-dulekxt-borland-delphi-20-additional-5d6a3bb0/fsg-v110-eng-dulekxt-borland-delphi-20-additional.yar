import "pe"
rule FSG_v110_Eng_dulekxt_Borland_Delphi_20_additional: PEiD
{
    strings:
        $a = { EB 01 4D 83 F6 4C 68 80 ?? ?? 00 EB 02 CD 20 5B EB 01 23 68 48 1C 2B 3A E8 02 00 00 00 38 }
    condition:
        $a at pe.entry_point

}