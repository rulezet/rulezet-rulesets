import "pe"
rule HideProtect_1016_SoftWar_Company_additional: PEiD
{
    strings:
        $a = { 90 90 90 E9 D8 ?? 05 00 95 ?? 53 00 95 4A 50 00 }
    condition:
        $a at pe.entry_point

}