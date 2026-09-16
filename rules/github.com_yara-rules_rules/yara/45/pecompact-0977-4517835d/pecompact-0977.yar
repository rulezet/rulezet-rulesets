import "pe"
rule PECompact_0977: PEiD
{
    strings:
        $a = { EB 06 68 00 00 00 00 C3 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB A0 86 40 00 87 DD 8B 85 2A 87 40 00 01 85 94 86 40 00 66 C7 85 91 86 40 00 90 90 BB E1 06 00 00 03 9D 2E 87 40 00 03 9D 2A 87 40 00 53 53 53 58 2D FB }
    condition:
        $a at pe.entry_point

}