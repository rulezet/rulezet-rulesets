import "pe"
rule LHA_Archive: PEiD
{
    strings:
        $a = { ?? ?? ?? 6C 68 35 }
        $b = { 6C 68 35 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}