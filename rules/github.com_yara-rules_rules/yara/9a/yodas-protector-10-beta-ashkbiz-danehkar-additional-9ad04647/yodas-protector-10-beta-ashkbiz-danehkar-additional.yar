import "pe"
rule yodas_Protector_10_beta_Ashkbiz_Danehkar_additional: PEiD
{
    strings:
        $a = { 55 8B EC 53 56 57 60 E8 00 00 00 00 5D 81 ED 4C 32 40 00 E8 03 00 00 00 EB 01 ?? B9 EA 47 40 00 81 E9 E9 32 40 00 8B D5 81 C2 E9 32 40 00 8D 3A 8B F7 33 C0 E8 04 00 00 00 90 EB 01 ?? E8 03 00 }
    condition:
        $a at pe.entry_point

}