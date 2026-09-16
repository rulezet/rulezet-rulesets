import "pe"
rule PECompact_110_beta_8: PEiD
{
    strings:
        $a = { EB 06 68 00 00 00 00 C3 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 70 40 00 87 DD 8B 85 9A 70 40 00 01 85 03 70 40 00 66 C7 85 00 70 40 00 90 90 01 85 92 70 40 00 BB 14 08 00 00 03 9D 9E 70 40 00 03 9D 9A 70 40 00 }
    condition:
        $a at pe.entry_point

}