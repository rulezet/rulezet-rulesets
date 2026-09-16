import "pe"
rule Shrinker_v34_additional: PEiD
{
    strings:
        $a = { 83 3D B4 ?? ?? ?? ?? 55 8B EC 56 57 75 6B 68 00 01 00 00 E8 ?? 0B 00 00 83 C4 04 8B 75 08 A3 B4 ?? ?? ?? 85 F6 74 23 83 7D 0C 03 77 1D 68 FF }
    condition:
        $a at pe.entry_point

}