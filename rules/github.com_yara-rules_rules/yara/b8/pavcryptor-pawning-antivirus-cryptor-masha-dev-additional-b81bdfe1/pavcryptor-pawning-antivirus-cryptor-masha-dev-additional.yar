import "pe"
rule PAVCryptor_Pawning_AntiVirus_Cryptor_masha_dev_additional: PEiD
{
    strings:
        $a = { 53 56 57 55 BB 2C ?? ?? 70 BE 00 30 00 70 BF 20 ?? ?? 70 80 7B 28 00 75 16 83 3F 00 74 11 8B 17 89 D0 33 D2 89 17 8B E8 FF D5 83 3F 00 75 EF 83 3D 04 30 00 70 00 74 06 FF 15 54 30 00 70 80 7B 28 02 75 0A 83 3E 00 75 05 33 C0 89 43 0C FF 15 1C 30 00 70 80 }
    condition:
        $a at pe.entry_point

}