import "pe"
rule MS_Run_Time_Library_1992_14_Hint_DOS_EP: PEiD
{
    strings:
        $a = { 1E 06 8C C8 8E D8 8C C0 A3 ?? ?? 83 C0 ?? A3 ?? ?? B4 30 }
    condition:
        $a at pe.entry_point

}