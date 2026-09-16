import "pe"
rule NoodleCrypt_v200_Eng_NoodleSpa_additional: PEiD
{
    strings:
        $a = { EB 01 9A E8 76 00 00 00 }
    condition:
        $a at pe.entry_point

}