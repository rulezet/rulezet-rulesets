import "pe"
rule VMProtect_v125_PolyTech: PEiD
{
    strings:
        $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 50 52 }
        $b = { 8B 45 00 83 C5 02 66 8B 00 66 89 45 00 E9 A5 06 00 00 8B 45 00 66 8B 55 04 83 C5 06 66 89 10 E9 }
        $c = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}