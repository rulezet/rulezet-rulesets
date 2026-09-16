import "pe"
rule ASPack_1083: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 5D 81 ED 0A 4A 44 00 BB 04 4A 44 00 03 DD 2B 9D B1 50 44 00 83 BD AC 50 44 00 00 89 9D BB 4E 44 00 0F 85 17 05 00 00 8D 85 D1 50 44 00 50 FF 95 94 51 44 00 89 85 CD 50 44 00 8B F8 8D 9D DE 50 44 00 53 50 FF 95 90 51 44 00 }
    condition:
        $a at pe.entry_point

}