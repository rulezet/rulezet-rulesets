import "pe"
rule Khrome_Crypt_03: PEiD
{
    strings:
        $a = { B9 EB 09 B8 05 FE EB FC 80 C4 3B EB F4 EB 37 90 FE DF DF DF DF DF DF DF DF DF DF DF DF DF DF FE DD 20 4B 68 72 6F 6D 65 20 43 72 79 70 74 20 DE FE DC DC DC DC DC DC DC DC DC DC DC DC DC DC FE EF 00 00 00 00 00 EB 02 66 BC D9 FF EB 02 66 BC }
    condition:
        $a at pe.entry_point

}