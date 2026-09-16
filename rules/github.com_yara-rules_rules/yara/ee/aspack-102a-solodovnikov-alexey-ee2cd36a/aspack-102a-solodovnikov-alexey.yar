import "pe"
rule ASPack_102a_Solodovnikov_Alexey: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 5D 81 ED 3E D9 43 00 B8 38 ?? ?? 00 03 C5 2B 85 0B DE 43 00 89 85 17 DE 43 00 80 BD 01 DE 43 00 00 75 15 FE 85 01 DE 43 00 E8 1D 00 00 00 E8 79 02 00 00 E8 12 03 00 00 8B 85 03 DE 43 00 03 85 17 DE 43 00 89 44 24 1C 61 FF }
    condition:
        $a at pe.entry_point

}