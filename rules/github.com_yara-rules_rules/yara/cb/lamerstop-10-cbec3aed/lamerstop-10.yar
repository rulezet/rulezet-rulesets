import "pe"
rule LamerStop_10: PEiD
{
    strings:
        $a = { E8 9D 01 05 B4 30 CD 21 33 C0 8E C0 26 A1 04 00 2E A3 79 01 26 A1 06 00 2E A3 77 01 BA 3F 01 FA 26 89 16 04 00 26 8C 0E 06 00 8B EC 9C 80 76 FF 01 9D 90 D1 89 00 84 36 90 5C FF 84 3B 90 E1 D8 84 14 90 29 84 06 90 E3 C8 84 18 90 8D 02 84 F7 }
    condition:
        $a at pe.entry_point

}