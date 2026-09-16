import "pe"
rule ASPack_v2000: PEiD
{
    strings:
        $a = { 60 E8 72 05 ?? ?? EB }
        $b = { 60 E8 70 05 00 00 EB 4C }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}