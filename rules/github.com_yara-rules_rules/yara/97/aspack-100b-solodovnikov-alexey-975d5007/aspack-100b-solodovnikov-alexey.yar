import "pe"
rule ASPack_100b_Solodovnikov_Alexey: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 5D 81 ED 92 1A 44 00 B8 8C 1A 44 00 03 C5 2B 85 CD 1D 44 00 89 85 D9 1D 44 00 80 BD C4 1D 44 }
    condition:
        $a at pe.entry_point

}