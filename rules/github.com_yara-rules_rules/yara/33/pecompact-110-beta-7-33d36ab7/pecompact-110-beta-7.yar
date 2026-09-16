import "pe"
rule PECompact_110_beta_7: PEiD
{
    strings:
        $a = { EB 06 68 00 00 00 00 C3 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 60 40 00 87 DD 8B 85 9A 60 40 00 01 85 03 60 40 00 66 C7 85 00 60 40 00 90 90 01 85 92 60 40 00 BB 14 08 00 00 03 9D 9E 60 40 00 03 9D 9A 60 40 00 }
    condition:
        $a at pe.entry_point

}