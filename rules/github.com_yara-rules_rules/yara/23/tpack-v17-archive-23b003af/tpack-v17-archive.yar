import "pe"
rule TPACK_v17_Archive: PEiD
{
    strings:
        $a = { ?? 54 50 41 43 ?? 31 2E 37 }
        $b = { 54 50 41 43 ?? 31 2E 37 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}