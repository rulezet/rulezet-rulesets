import "pe"
rule EXECryptor_2xx_max_compressed_resources_wwwstrongbitcom: PEiD
{
    strings:
        $a = { 55 8B EC 83 C4 EC FC 53 57 56 89 45 FC 89 55 F8 89 C6 89 D7 66 81 3E 4A 43 0F 85 23 01 00 00 83 C6 0A C7 45 F4 08 00 00 00 31 DB BA 00 00 00 80 43 31 C0 E8 11 01 00 00 73 0E 8B 4D F0 E8 1F 01 00 00 02 45 EF AA EB E9 E8 FC 00 00 00 0F 82 97 00 00 00 E8 F1 }
    condition:
        $a at pe.entry_point

}