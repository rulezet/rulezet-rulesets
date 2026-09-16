import "pe"
rule Microsoft_CAB_SFX_module: PEiD
{
    strings:
        $a = { 55 8B EC 83 EC 44 56 FF 15 94 13 42 ?? 8B F0 B1 22 8A 06 3A C1 75 13 8A 46 01 46 3A C1 74 04 84 C0 75 F4 38 0E 75 0D 46 EB 0A 3C 20 7E }
        $b = { 55 8B EC 83 EC 44 56 FF 15 ?? 10 00 01 8B F0 8A 06 3C 22 75 14 8A 46 01 46 84 C0 74 04 3C 22 75 F4 80 3E 22 75 0D ?? EB 0A 3C 20 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}