import "pe"
rule Shrinker_32: PEiD
{
    strings:
        $a = { 55 8B EC 56 57 75 65 68 00 01 00 00 E8 F1 E6 FF FF 83 C4 04 }
    condition:
        $a at pe.entry_point

}