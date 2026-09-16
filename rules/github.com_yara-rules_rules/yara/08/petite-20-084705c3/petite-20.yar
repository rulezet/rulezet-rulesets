import "pe"
rule Petite_20: PEiD
{
    strings:
        $a = { B8 00 00 00 00 66 9C 60 50 8B D8 03 00 68 54 BC 00 00 6A 00 FF 50 18 8B CC 8D A0 54 BC 00 00 8B C3 8D 90 E0 15 00 00 68 00 00 00 00 51 50 80 04 24 08 50 80 04 24 42 50 80 04 24 61 50 80 04 24 9D 50 80 04 24 BB 83 3A 00 0F 84 E3 00 00 FF 8B }
    condition:
        $a at pe.entry_point

}