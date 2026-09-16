import "pe"
rule MINI_COM: PEiD
{
    strings:
        $a = { B8 00 00 BA 00 00 3B C4 73 46 8B C4 2D 24 03 90 25 F0 FF 8B F8 B9 92 00 90 BE 6C 01 FC F3 A5 8B D8 B1 04 D3 EB 8C D9 03 D9 53 33 DB 53 CB 00 4D 49 4E 49 20 28 43 29 20 76 31 2E 30 31 20 62 79 20 41 6C 62 65 72 74 20 53 65 6E 20 31 39 39 32 }
    condition:
        $a at pe.entry_point

}