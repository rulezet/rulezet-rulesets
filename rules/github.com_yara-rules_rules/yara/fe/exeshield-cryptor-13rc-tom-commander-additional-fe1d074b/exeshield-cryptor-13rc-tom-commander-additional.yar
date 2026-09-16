import "pe"
rule ExeShield_Cryptor_13RC_Tom_Commander_additional: PEiD
{
    strings:
        $a = { 55 8B EC 53 56 57 60 E8 00 00 00 00 5D 81 ED 8C 21 40 00 B9 51 2D 40 00 81 E9 E6 21 40 00 8B D5 81 C2 E6 21 40 00 8D 3A 8B F7 33 C0 EB 04 90 EB 01 C2 AC }
    condition:
        $a at pe.entry_point

}