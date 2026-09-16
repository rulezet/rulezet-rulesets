import "pe"
rule FASM_v13x: PEiD
{
    strings:
        $a = { E8 ?? 6E ?? ?? 55 89 E5 8B 7D 0C 8B 75 08 89 F8 8B 5D 10 }
        $b = { 6A ?? FF 15 ?? ?? ?? ?? A3 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}