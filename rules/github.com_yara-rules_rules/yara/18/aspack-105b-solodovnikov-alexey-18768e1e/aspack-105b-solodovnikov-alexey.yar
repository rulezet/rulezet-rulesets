import "pe"
rule ASPack_105b_Solodovnikov_Alexey: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 5D 81 ED CE 3A 44 00 B8 C8 3A 44 00 03 C5 2B 85 B5 3E 44 00 89 85 C1 3E 44 00 80 BD AC 3E 44 }
    condition:
        $a at pe.entry_point

}