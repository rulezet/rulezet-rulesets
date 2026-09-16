import "pe"
rule Hyper_Archive: PEiD
{
    strings:
        $a = { 1A 53 54 }
        $b = { 1A 48 50 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}