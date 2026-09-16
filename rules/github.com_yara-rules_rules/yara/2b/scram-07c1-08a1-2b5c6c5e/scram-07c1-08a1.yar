import "pe"
rule Scram_07c1_08a1: PEiD
{
    strings:
        $a = { 53 43 52 41 4D B4 30 CD 21 3C 02 77 02 CD 20 BC 3A 01 B9 00 00 8B FC B2 00 58 4C F6 D8 2A C2 D2 C8 FE CA 32 D1 81 FF D1 02 73 02 EB 09 81 FF 9B 03 73 03 47 EB 01 AA 49 75 DF }
    condition:
        $a at pe.entry_point

}