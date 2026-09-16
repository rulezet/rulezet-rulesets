import "pe"
rule PESHiELD_v025: PEiD
{
    strings:
        $a = { 5D 83 ED 06 EB 02 EA 04 }
        $b = { 60 E8 2B 00 00 00 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}