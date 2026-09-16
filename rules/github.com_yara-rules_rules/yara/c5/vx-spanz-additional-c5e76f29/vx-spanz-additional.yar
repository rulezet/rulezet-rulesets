import "pe"
rule Vx_Spanz_additional: PEiD
{
    strings:
        $a = { E8 00 00 5E 81 EE ?? ?? 8D 94 ?? ?? B4 1A CD 21 C7 84 }
    condition:
        $a at pe.entry_point

}