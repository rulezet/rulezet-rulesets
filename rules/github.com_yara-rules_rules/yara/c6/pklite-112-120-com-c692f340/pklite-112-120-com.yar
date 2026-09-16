import "pe"
rule PKLite_112_120_COM: PEiD
{
    strings:
        $a = { B8 00 00 BA 00 00 3B C4 73 67 8B C4 2D 44 03 25 F0 FF 8B F8 B9 A2 00 BE 7C 01 FC F3 A5 8B D8 B1 04 D3 EB 8C D9 03 D9 53 33 DB 53 CB 0C 01 50 4B 4C 49 54 45 20 43 6F 70 72 2E 20 31 39 39 31 20 }
    condition:
        $a at pe.entry_point

}