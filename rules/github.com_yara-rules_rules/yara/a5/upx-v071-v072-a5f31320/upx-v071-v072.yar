import "pe"
rule UPX_v071_v072: PEiD
{
    strings:
        $a = { 80 7C 24 08 01 0F 85 ?? 60 BE 8D BE 57 83 CD }
        $b = { 60 E8 00 00 00 00 83 CD FF 31 DB 5E 8D BE FA ?? ?? FF 57 66 81 87 ?? ?? ?? ?? ?? ?? 81 C6 B3 01 ?? ?? EB 0A ?? ?? ?? ?? 8A 06 46 88 07 47 01 DB 75 07 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}