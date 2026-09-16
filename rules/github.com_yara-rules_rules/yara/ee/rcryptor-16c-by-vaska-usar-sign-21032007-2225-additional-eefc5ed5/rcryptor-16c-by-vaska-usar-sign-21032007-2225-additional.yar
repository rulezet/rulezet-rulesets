import "pe"
rule RCryptor_16c_by_Vaska_UsAr_sign_21032007_2225_additional: PEiD
{
    strings:
        $a = { 33 D0 68 40 A1 14 13 FF D2 B8 00 10 14 13 3D 24 C0 14 13 74 06 80 30 BB 40 EB F3 33 C0 C3 }
    condition:
        $a at pe.entry_point

}