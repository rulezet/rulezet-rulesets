import "pe"
rule Adobe_PhotoShop_Plugin: PEiD
{
    strings:
        $a = { 83 7C 24 08 01 75 09 8B 44 24 04 A3 00 00 00 10 B8 01 00 00 00 C2 0C 00 8D 64 24 00 8D 64 24 00 56 57 8B 74 24 0C 8B 7E 0C 83 C7 0C 83 3F }
    condition:
        $a at pe.entry_point

}