import "pe"
rule MS_Run_Time_Library_1992_11_additional: PEiD
{
    strings:
        $a = { B4 51 CD 21 8E DB B8 ?? ?? 83 E8 ?? 8E C0 33 F6 33 FF B9 ?? ?? FC F3 A5 }
    condition:
        $a at pe.entry_point

}