import "pe"
rule PECompact_140_141: PEiD
{
    strings:
        $a = { EB 06 68 00 00 00 00 C3 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F A0 40 00 87 DD 8B 85 A6 A0 40 00 01 85 03 A0 40 00 66 C7 85 00 A0 40 00 90 90 01 85 9E A0 40 00 BB C3 11 00 00 03 9D AA A0 40 00 03 9D A6 A0 40 00 }
    condition:
        $a at pe.entry_point

}