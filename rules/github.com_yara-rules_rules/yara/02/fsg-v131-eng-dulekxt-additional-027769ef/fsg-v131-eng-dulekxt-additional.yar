import "pe"
rule FSG_v131_Eng_dulekxt_additional: PEiD
{
    strings:
        $a = { BB ?? ?? BA ?? ?? 81 C3 07 00 B8 40 B4 B1 04 D3 E8 03 C3 8C D9 49 8E C1 26 03 0E 03 00 2B }
    condition:
        $a at pe.entry_point

}