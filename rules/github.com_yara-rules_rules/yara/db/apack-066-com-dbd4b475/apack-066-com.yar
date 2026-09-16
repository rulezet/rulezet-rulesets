import "pe"
rule aPack_066_COM: PEiD
{
    strings:
        $a = { 8C C8 05 00 00 8E C0 59 8E D0 51 BE 9C 01 BF 00 01 50 57 FC B6 01 BD 7D 01 FF D5 73 5D FF D5 73 1C FF D5 73 3B BB 94 01 33 C9 FF D3 FF D3 FF D3 FF D3 8B D9 B1 01 85 DB 75 36 93 EB 38 E8 48 00 49 49 75 06 2E A1 00 01 EB 08 49 AC 8A E1 2E A3 }
    condition:
        $a at pe.entry_point

}