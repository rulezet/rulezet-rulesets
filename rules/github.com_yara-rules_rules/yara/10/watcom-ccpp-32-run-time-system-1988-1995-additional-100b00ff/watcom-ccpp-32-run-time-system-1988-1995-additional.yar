import "pe"
rule WATCOM_CCpp_32_Run_Time_System_1988_1995_additional: PEiD
{
    strings:
        $a = { E9 ?? ?? ?? ?? ?? ?? ?? ?? 57 41 54 43 4F 4D 20 43 2F 43 2B 2B 33 32 20 52 75 6E 2D 54 }
    condition:
        $a at pe.entry_point

}