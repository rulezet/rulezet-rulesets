import "pe"
rule ASProtect_v11_BRS: PEiD
{
    strings:
        $a = { 68 01 }
        $b = { 60 E9 ?? 05 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}