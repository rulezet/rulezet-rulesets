import "pe"
rule ASPack_v2001: PEiD
{
    strings:
        $a = { 60 E8 72 05 ?? ?? EB 33 87 DB }
        $b = { 60 E8 72 05 00 00 EB 4C }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}