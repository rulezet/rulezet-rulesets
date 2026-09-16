import "pe"
rule RCryptor_16c_by_Vaska_UsAr_sign_21032007_2225: PEiD
{
    strings:
        $a = { 8B C7 03 04 24 2B C7 80 38 50 0F 85 1B 8B 1F FF 68 40 A1 14 13 B8 00 10 14 13 3D 24 C0 14 13 74 06 80 30 F2 40 EB F3 B8 8C 20 18 13 3D B9 27 18 13 74 06 80 30 E8 40 EB F3 C3 }
    condition:
        $a at pe.entry_point

}