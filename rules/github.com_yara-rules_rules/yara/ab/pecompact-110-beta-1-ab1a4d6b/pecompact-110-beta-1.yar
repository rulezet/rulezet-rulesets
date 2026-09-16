import "pe"
rule PECompact_110_beta_1: PEiD
{
    strings:
        $a = { EB 06 68 00 00 00 00 C3 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 28 63 40 00 87 DD 8B 85 AD 63 40 00 01 85 1C 63 40 00 66 C7 85 19 63 40 00 90 90 BB D6 0A 00 00 03 9D B1 63 40 00 03 9D AD 63 40 00 53 53 53 58 2D 83 }
    condition:
        $a at pe.entry_point

}