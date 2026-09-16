import "pe"
rule Crypt_17_EXE: PEiD
{
    strings:
        $a = { 0E 17 9C 58 F6 C4 01 74 03 E9 98 00 1E B0 02 E6 21 8C DA 83 C2 10 8E DA 8E C2 BB 00 00 BA 00 00 85 D2 74 29 B4 01 33 FF 33 F6 B9 00 F0 AC 32 C4 C0 C4 03 02 E1 2E 00 06 22 01 AA E2 F0 8C D8 05 00 0F 8E D8 8E C0 4A 85 D2 74 02 EB D7 60 B4 30 }
    condition:
        $a at pe.entry_point

}