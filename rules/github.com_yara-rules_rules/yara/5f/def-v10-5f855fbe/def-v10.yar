import "pe"
rule DEF_v10: PEiD
{
    strings:
        $a = { BE ?? 01 40 00 6A 05 59 80 7E 07 00 74 11 8B 46 }
        $b = { BE ?? 01 40 00 6A ?? 59 80 7E 07 00 74 11 8B 46 0C 05 00 00 40 00 8B 56 10 30 10 40 4A 75 FA 83 C6 28 E2 E4 68 ?? 10 40 00 C3 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}