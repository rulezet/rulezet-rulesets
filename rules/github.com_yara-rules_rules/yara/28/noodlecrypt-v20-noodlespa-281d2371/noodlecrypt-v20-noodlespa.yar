import "pe"
rule NoodleCrypt_v20_NoodleSpa: PEiD
{
    strings:
        $a = { EB 01 9A E8 3D 00 00 00 EB 01 9A E8 EB 01 00 00 EB 01 9A E8 2C 04 00 00 EB 01 }
    condition:
        $a at pe.entry_point

}