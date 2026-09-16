import "pe"
rule WATCOM_CCpp_32_Run_Time_System_1988_1995: PEiD
{
    strings:
        $a = { FB 83 89 E3 89 89 66 66 BB 29 C0 B4 30 CD }
        $b = { E9 ?? ?? ?? ?? ?? ?? ?? ?? 57 41 54 43 4F 4D 20 43 2F 43 2B 2B 33 32 20 52 75 6E 2D 54 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}