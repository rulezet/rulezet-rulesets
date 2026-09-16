import "pe"
rule Stones_PE_Encrypter_20: PEiD
{
    strings:
        $a = { 53 51 52 56 57 55 E8 00 00 00 00 5D 81 ED 42 30 40 00 FF 95 32 35 40 00 B8 37 30 40 00 03 C5 2B 85 1B 34 40 00 89 85 27 34 40 00 83 BD 0F 34 40 00 00 75 1D 90 90 90 90 C7 85 0F 34 40 00 01 00 00 00 E8 1E 00 00 00 E8 25 02 00 00 E8 DA 02 00 }
    condition:
        $a at pe.entry_point

}