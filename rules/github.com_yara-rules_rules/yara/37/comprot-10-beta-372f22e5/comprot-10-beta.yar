import "pe"
rule ComProt_10_beta: PEiD
{
    strings:
        $a = { E8 00 00 5E 8B EE 81 ED 03 01 8D B6 16 01 B9 0A 01 F6 14 46 E2 FB 4B F6 72 69 28 FE 32 DE 4B FC 32 EF 76 69 DA FD 44 FE FF 4B FF 32 E9 C3 FF 8B 07 C3 F2 8B C8 C3 F7 8A E7 7C 04 FE 8B 14 4F DF 17 7F FF 01 34 01 71 DA FD 17 88 FF 17 8B FF 14 }
    condition:
        $a at pe.entry_point

}