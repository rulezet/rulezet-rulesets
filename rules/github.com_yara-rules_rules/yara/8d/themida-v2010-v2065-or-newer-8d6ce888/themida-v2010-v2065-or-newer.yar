import "pe"
rule Themida_v2010_v2065_or_newer: PEiD
{
    strings:
        $a = { 83 EC 04 50 53 E8 ?? 00 00 00 CC 58 8B D8 40 2D 00 ?? ?? 00 2D ?? ?? ?? 00 05 ?? ?? ?? 00 80 3B CC 75 19 C6 03 00 BB 00 10 00 00 68 }
    condition:
        $a at pe.entry_point

}