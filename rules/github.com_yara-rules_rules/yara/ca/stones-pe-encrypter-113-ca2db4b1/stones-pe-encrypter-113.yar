import "pe"
rule Stones_PE_Encrypter_113: PEiD
{
    strings:
        $a = { 55 57 56 52 51 53 E8 00 00 00 00 5D 8B D5 81 ED 97 3B 40 00 2B 95 2D 3C 40 00 83 EA 0B 89 95 36 3C 40 00 01 95 24 3C 40 00 01 95 28 3C 40 00 80 BD 2C 3C 40 00 00 75 4A C6 85 2C 3C 40 00 01 8D B5 35 3C 40 00 0F B6 36 8B FD 8D 9D 36 3C 40 00 }
    condition:
        $a at pe.entry_point

}