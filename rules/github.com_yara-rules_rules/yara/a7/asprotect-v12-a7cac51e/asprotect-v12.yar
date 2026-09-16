import "pe"
rule ASProtect_v12: PEiD
{
    strings:
        $a = { 68 01 C3 AA ?? }
        $b = { 68 01 ?? ?? ?? C3 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}