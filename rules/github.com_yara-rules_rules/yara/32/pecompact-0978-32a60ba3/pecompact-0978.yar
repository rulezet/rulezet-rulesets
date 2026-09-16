import "pe"
rule PECompact_0978: PEiD
{
    strings:
        $a = { EB 06 68 00 00 00 00 C3 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 24 88 40 00 87 DD 8B 85 A9 88 40 00 01 85 18 88 40 00 66 C7 85 15 88 40 00 90 90 BB A8 09 00 00 03 9D AD 88 40 00 03 9D A9 88 40 00 53 53 53 58 2D 7F }
    condition:
        $a at pe.entry_point

}