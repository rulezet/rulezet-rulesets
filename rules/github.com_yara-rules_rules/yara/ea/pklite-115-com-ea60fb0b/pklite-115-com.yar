import "pe"
rule PKLite_115_COM: PEiD
{
    strings:
        $a = { B8 00 00 BA 00 00 3B C4 73 69 8B C4 2D 44 03 90 25 F0 FF 8B F8 B9 A2 00 90 BE 7E 01 FC F3 A5 8B D8 B1 04 D3 EB 8C D9 03 D9 53 33 DB 53 CB 0E 01 }
    condition:
        $a at pe.entry_point

}