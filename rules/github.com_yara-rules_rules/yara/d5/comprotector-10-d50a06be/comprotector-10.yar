import "pe"
rule ComProtector_10: PEiD
{
    strings:
        $a = { B9 00 00 BB 03 01 BF 00 01 2E 8A 07 34 B9 FE C8 C0 C0 9A 2E 88 05 2E 00 0D 2E 00 2D 47 43 E2 E9 B9 CD 01 E8 00 00 5B 83 C3 12 90 2E C0 07 A4 2E 30 0F 2E 30 2F 43 E2 F3 42 DC AC 09 94 A0 C0 6C D7 BC 2C 0F 00 A2 6B F2 0F CD 7D ED AC 89 29 99 }
    condition:
        $a at pe.entry_point

}