import "pe"
rule Alloy_104142000: PEiD
{
    strings:
        $a = { 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 07 20 40 00 87 DD 6A 04 68 00 10 00 00 68 00 02 00 00 6A 00 FF 95 46 23 40 00 0B C0 0F 84 A6 01 00 00 89 85 CC 22 40 00 83 BD 90 22 40 00 01 74 04 8B F8 EB 18 68 D8 01 00 00 }
    condition:
        $a at pe.entry_point

}