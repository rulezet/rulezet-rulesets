import "pe"
rule VMProtect_V1X_PolyTech: PEiD
{
    strings:
        $a = { 9C 60 68 00 00 00 00 8B 74 24 28 BF ?? ?? ?? ?? FC 89 F3 03 34 24 AC 00 D8 }
    condition:
        $a at pe.entry_point

}