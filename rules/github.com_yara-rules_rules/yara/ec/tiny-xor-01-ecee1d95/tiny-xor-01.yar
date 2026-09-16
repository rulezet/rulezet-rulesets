import "pe"
rule Tiny_Xor_01: PEiD
{
    strings:
        $a = { FC B8 00 00 BB 00 00 B9 00 00 BE 03 01 30 04 02 C3 86 C4 86 DF 46 E2 F5 BE 00 01 C7 04 00 00 C6 44 02 00 33 C0 33 DB 33 C9 FF E6 }
    condition:
        $a at pe.entry_point

}