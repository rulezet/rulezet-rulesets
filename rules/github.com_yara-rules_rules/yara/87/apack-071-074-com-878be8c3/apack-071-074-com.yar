import "pe"
rule aPack_071_074_COM: PEiD
{
    strings:
        $a = { 8C C8 05 00 00 8E C0 59 8E D0 51 BE 9B 01 BF 00 01 50 57 FC B6 01 BD 7C 01 FF D5 73 5C FF D5 73 1C FF D5 73 3E BB 93 01 33 C9 FF D3 FF D3 FF D3 FF D3 8B D9 B1 01 85 DB 75 35 93 EB 37 E8 47 00 49 49 75 0A 2E 8B 1E 00 01 E8 3B 00 EB 21 49 AC }
    condition:
        $a at pe.entry_point

}