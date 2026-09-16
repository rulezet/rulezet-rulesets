import "pe"
rule eXPressor_10_beta_CGSoftLabs: PEiD
{
    strings:
        $a = { E8 53 03 00 00 8B F0 56 56 E8 98 03 00 00 8B C8 }
        $b = { E9 35 14 00 00 E9 31 13 00 00 E9 98 12 00 00 E9 EF 0C 00 00 E9 42 13 00 00 E9 E9 02 00 00 E9 EF 0B 00 00 E9 1B 0D 00 00 CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}