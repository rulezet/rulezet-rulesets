import "pe"
rule Goats_Mutilator_v16_Goat_e0f: PEiD
{
    strings:
        $a = { E8 E8 01 ?? ?? 60 01 AD B3 27 40 ?? 68 }
        $b = { E8 EA 0B 00 00 ?? ?? ?? 8B 1C 79 F6 63 D8 8D 22 B0 BF F6 49 08 C3 02 BD 3B 6C 29 46 13 28 5D }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}