import "pe"
rule WATCOM_CCpp_32_Run_Time_System_1988_1995_Hint_WIN_EP: PEiD
{
    strings:
        $a = { E9 ?? ?? ?? ?? ?? ?? ?? ?? 57 41 54 43 4F 4D ?? 43 2F 43 2B 2B 33 32 ?? 52 75 }
    condition:
        $a at pe.entry_point

}