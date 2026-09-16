import "pe"
rule ASPack_103b_Solodovnikov_Alexey: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 5D 81 ED AE 98 43 00 B8 A8 98 43 00 03 C5 2B 85 18 9D 43 00 89 85 24 9D 43 00 80 BD 0E 9D 43 }
    condition:
        $a at pe.entry_point

}