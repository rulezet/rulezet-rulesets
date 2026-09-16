import "pe"
rule PUNiSHER_V15_Demo_FEUERRADER: PEiD
{
    strings:
        $a = { EB 04 83 A4 BC CE 60 EB 04 80 BC 04 11 E8 00 00 00 00 }
        $b = { 3F 00 00 80 66 20 ?? 00 7E 20 ?? 00 92 20 ?? 00 A4 20 ?? 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}