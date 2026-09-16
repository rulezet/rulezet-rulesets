import "pe"
rule ASPack_2xwithouth_Poly_Solodovnikov_Alexey: PEiD
{
    strings:
        $a = { ?? 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB EC FF FF FF 03 DD 81 EB 00 40 1C 00 }
    condition:
        $a at pe.entry_point

}