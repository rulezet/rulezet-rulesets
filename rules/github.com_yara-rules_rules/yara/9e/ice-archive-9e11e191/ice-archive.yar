import "pe"
rule ICE_Archive: PEiD
{
    strings:
        $a = { ?? ?? 2D 6C 68 ?? 2D }
        $b = { 2D 6C 68 ?? 2D }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}