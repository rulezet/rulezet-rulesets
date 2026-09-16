import "pe"
rule FSG_v110_Eng_dulekxt_Borland_Delphi_20_: PEiD
{
    strings:
        $a = { EB 01 56 E8 02 00 00 00 B2 D9 59 68 80 ?? 41 00 E8 02 00 00 00 65 32 59 5E EB 02 CD 20 BB }
    condition:
        $a at pe.entry_point

}