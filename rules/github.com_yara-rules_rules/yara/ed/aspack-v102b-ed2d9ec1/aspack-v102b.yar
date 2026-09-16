import "pe"
rule ASPack_v102b: PEiD
{
    strings:
        $a = { 60 E8 ?? ?? ?? ?? 5D 81 ED 96 78 43 ?? B8 90 78 43 ?? 03 }
        $b = { 60 E8 00 00 00 00 5D 81 ED 96 78 43 00 B8 90 78 43 00 03 C5 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}