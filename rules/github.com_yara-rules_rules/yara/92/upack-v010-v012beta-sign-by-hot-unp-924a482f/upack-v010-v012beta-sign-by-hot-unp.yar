import "pe"
rule Upack_v010_v012Beta_Sign_by_hot_UNP: PEiD
{
    strings:
        $a = { BE 48 01 ?? ?? ?? ?? ?? 95 A5 33 C0 }
        $b = { BE B0 11 ?? ?? AD 50 FF 76 34 EB 7C 48 01 ?? ?? 0B 01 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 18 10 00 00 10 00 00 00 00 ?? ?? ?? 00 00 ?? ?? 00 10 00 00 00 02 00 00 04 00 00 00 00 00 3A 00 04 00 00 00 00 00 00 00 00 ?? ?? ?? 00 02 00 00 00 00 00 00 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}