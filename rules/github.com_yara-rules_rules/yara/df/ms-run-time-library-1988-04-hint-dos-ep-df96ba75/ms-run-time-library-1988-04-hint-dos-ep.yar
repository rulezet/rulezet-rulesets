import "pe"
rule MS_Run_Time_Library_1988_04_Hint_DOS_EP: PEiD
{
    strings:
        $a = { 1E B8 ?? ?? 8E D8 B4 30 CD 21 3C 02 73 ?? BA ?? ?? E8 ?? ?? 06 33 C0 50 CB }
    condition:
        $a at pe.entry_point

}