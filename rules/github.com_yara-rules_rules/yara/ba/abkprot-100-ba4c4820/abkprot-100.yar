import "pe"
rule ABKprot_100: PEiD
{
    strings:
        $a = { B4 30 CD 21 86 E0 3D FF 02 73 02 CD 20 9C 8C C0 06 5B 59 51 53 BA 1C 01 87 F2 56 CF 0E 1F 0E 07 BF 00 00 BE 2F 01 B9 22 00 F3 A4 68 00 00 C3 BE 51 01 BF 00 01 B9 00 00 AC 33 C7 35 24 24 AA E2 F7 33 C0 8B D8 8B C8 8B D0 8B F0 8B F8 68 00 01 }
    condition:
        $a at pe.entry_point

}