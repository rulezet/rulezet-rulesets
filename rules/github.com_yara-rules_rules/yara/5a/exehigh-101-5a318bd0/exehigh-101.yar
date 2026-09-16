import "pe"
rule EXEHigh_101: PEiD
{
    strings:
        $a = { 8C CA 8B 2E 01 00 8E DA 8C 06 90 06 8C DA 2B EA 8B 3E 94 06 81 FF 00 01 73 07 BF 00 01 89 3E 94 06 81 C7 DE 16 03 3E 92 06 B1 04 D3 EF 47 D3 E7 FA 8E D2 8B E7 FB E8 00 00 56 57 55 8B EC B4 4A 8E 06 90 06 BB FF FF CD 21 B4 4A 8E 06 90 06 CD }
    condition:
        $a at pe.entry_point

}