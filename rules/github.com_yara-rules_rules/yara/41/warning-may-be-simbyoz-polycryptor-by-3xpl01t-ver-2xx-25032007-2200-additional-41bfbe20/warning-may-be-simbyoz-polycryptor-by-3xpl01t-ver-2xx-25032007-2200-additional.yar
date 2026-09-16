import "pe"
rule Warning_may_be_SimbyOZ_polycryptor_by_3xpl01t_ver_2xx_25032007_2200_additional: PEiD
{
    strings:
        $a = { 57 57 8D 7C 24 04 50 B8 00 D0 17 13 AB 58 5F C3 00 00 }
    condition:
        $a at pe.entry_point

}