import "pe"
rule ASPack_v106b: PEiD
{
    strings:
        $a = { 90 90 75 ?? }
        $b = { 90 90 90 75 00 E9 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}