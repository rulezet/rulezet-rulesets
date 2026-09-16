import "pe"
rule FSG_v110_Eng_dulekxt_Borland_Delphi_Borland_Cue: PEiD
{
    strings:
        $a = { 2B C2 E8 02 00 00 00 95 4A 59 8D 3D 52 F1 2A E8 C1 C8 1C BE 2E ?? ?? 18 EB 02 AB A0 03 F7 }
    condition:
        $a at pe.entry_point

}