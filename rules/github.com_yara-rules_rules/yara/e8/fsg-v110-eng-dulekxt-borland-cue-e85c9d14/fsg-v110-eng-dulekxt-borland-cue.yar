import "pe"
rule FSG_v110_Eng_dulekxt_Borland_Cue: PEiD
{
    strings:
        $a = { 23 CA EB 02 5A 0D E8 02 00 00 00 6A 35 58 C1 C9 10 BE 80 ?? ?? 00 0F B6 C9 EB 02 CD 20 BB }
    condition:
        $a at pe.entry_point

}