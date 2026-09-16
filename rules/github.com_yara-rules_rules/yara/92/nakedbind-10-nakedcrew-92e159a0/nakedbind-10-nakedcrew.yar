import "pe"
rule Nakedbind_10_nakedcrew: PEiD
{
    strings:
        $a = { 64 8B 38 48 8B C8 F2 AF AF 8B 1F 66 33 DB 66 81 3B 4D 5A 74 08 81 EB 00 00 }
    condition:
        $a at pe.entry_point

}