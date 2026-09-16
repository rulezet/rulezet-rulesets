import "pe"
rule RCryptor_16_by_Vaska_Damrai_sign_20032007_2041: PEiD
{
    strings:
        $a = { 83 2C 24 4F 68 40 A1 14 13 FF 54 24 04 83 44 24 04 4F B8 00 10 14 13 3D 24 C0 14 13 74 06 80 30 2B 40 EB F3 B8 8C 20 18 13 3D B9 27 18 13 74 06 80 30 19 40 EB F3 E8 00 00 00 00 C3 }
        $b = { 33 D0 68 40 A1 14 13 FF D2 B8 00 10 14 13 3D 24 C0 14 13 74 06 80 30 BB 40 EB F3 33 C0 C3 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}