import "pe"
rule Vaccine_103_110: PEiD
{
    strings:
        $a = { FA 33 DB B9 00 00 0E 1F 33 F6 FC AD 35 00 00 03 D8 E2 F8 81 FB 00 00 74 42 E8 26 00 94 A0 A9 AB 20 A8 A7 AC A5 AD A5 AD 21 20 8F E0 AE A4 AE AB A6 A0 E2 EC 20 28 79 2F 6E 29 3F 20 07 24 00 01 00 00 B4 09 5A 8B F2 CD 21 C6 04 02 B4 0A CD 21 }
    condition:
        $a at pe.entry_point

}