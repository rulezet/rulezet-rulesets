import "pe"
rule yodas_Protector_10x_Ashkbiz_Danehkar: PEiD
{
    strings:
        $a = { 55 8B EC 53 56 57 E8 03 00 00 00 EB 01 }
        $b = { 55 8B EC 53 56 57 60 E8 00 00 00 00 5D 81 ED 4C 32 40 00 E8 03 00 00 00 EB 01 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}