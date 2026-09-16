import "pe"
rule yodas_Crypter_13_Ashkbiz_Danehkar_additional: PEiD
{
    strings:
        $a = { 55 8B EC 53 56 57 60 E8 00 00 00 00 5D 81 ED 6C 28 40 00 B9 5D 34 40 00 }
    condition:
        $a at pe.entry_point

}