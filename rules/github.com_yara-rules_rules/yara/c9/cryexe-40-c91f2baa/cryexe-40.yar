import "pe"
rule CryEXE_40: PEiD
{
    strings:
        $a = { E9 A1 FF E8 5C FF 55 E9 08 00 A5 12 BB 06 00 E8 95 FF E9 62 FF B9 FE 0C BE 0B 0F 2E 8A 14 89 F3 80 C2 46 80 F2 73 81 F3 E4 35 80 EA 22 30 DA 30 FA 2E 88 14 4E 49 74 02 EB E1 E5 46 C2 A3 2B 4B F8 59 54 DC 59 09 F4 A5 01 52 F5 56 B2 D3 7E 1B }
    condition:
        $a at pe.entry_point

}