import "pe"
rule ASPack_212withouth_Poly_Solodovnikov_Alexey: PEiD
{
    strings:
        $a = { ?? E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 }
    condition:
        $a at pe.entry_point

}