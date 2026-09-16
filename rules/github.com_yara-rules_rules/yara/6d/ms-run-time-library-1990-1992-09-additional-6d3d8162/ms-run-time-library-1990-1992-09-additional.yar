import "pe"
rule MS_Run_Time_Library_1990_1992_09_additional: PEiD
{
    strings:
        $a = { B4 30 CD 21 3C 02 73 ?? C3 8C DF 8B 36 ?? ?? 2E }
    condition:
        $a at pe.entry_point

}