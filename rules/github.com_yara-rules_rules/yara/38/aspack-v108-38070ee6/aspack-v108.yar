import "pe"
rule ASPack_v108: PEiD
{
    strings:
        $a = { 90 90 75 01 FF }
        $b = { 90 75 01 FF E9 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}