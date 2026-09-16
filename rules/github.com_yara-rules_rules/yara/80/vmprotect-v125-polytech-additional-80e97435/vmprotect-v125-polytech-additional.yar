import "pe"
rule _VMProtect_v125_PolyTech_additional: PEiD
{
    strings:
        $a = { 8B 45 00 83 C5 02 66 8B 00 66 89 45 00 E9 A5 06 00 00 8B 45 00 66 8B 55 04 83 C5 06 66 89 10 E9 }
    condition:
        $a at pe.entry_point

}