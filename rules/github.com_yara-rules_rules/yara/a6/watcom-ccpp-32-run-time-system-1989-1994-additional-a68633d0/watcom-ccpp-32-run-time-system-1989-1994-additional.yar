import "pe"
rule WATCOM_CCpp_32_Run_Time_System_1989_1994_additional: PEiD
{
    strings:
        $a = { 0E 1F 8C C6 B4 ?? 50 BB ?? ?? CD 21 73 ?? 58 CD 21 72 }
    condition:
        $a at pe.entry_point

}