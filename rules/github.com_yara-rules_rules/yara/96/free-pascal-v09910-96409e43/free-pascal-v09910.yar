import "pe"
rule Free_Pascal_v09910: PEiD
{
    strings:
        $a = { 64 A1 55 89 E5 6A FF 68 68 9A 10 40 }
        $b = { C6 05 ?? ?? 40 00 ?? E8 ?? ?? 00 00 }
        $c = { E8 00 6E 00 00 55 89 E5 8B 7D 0C 8B 75 08 89 F8 8B 5D 10 29 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}