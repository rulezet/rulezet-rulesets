import "pe"
rule ASProtect_v11_MTEb: PEiD
{
    strings:
        $a = { 90 60 E8 1B E9 }
        $b = { 90 60 E9 ?? 04 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}