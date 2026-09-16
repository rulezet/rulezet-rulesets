import "pe"
rule dUP_2x_Patcher_wwwdiablo2oo2cjbnet_additional: PEiD
{
    strings:
        $a = { 8B CB 85 C9 74 ?? 80 3A 01 74 08 AC AE 75 0A 42 49 EB EF 47 46 42 49 EB E9 }
    condition:
        $a at pe.entry_point

}