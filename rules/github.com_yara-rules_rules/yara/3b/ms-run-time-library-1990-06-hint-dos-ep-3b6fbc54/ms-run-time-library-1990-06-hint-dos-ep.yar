import "pe"
rule MS_Run_Time_Library_1990_06_Hint_DOS_EP: PEiD
{
    strings:
        $a = { EB ?? B4 30 CD 21 86 E0 2E A3 ?? ?? 3D ?? ?? 73 }
    condition:
        $a at pe.entry_point

}