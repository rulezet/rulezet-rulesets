import "pe"
rule ACE_Archive: PEiD
{
    strings:
        $a = { ?? ?? ?? ?? ?? ?? ?? 2A 2A 41 43 45 2A 2A }
        $b = { 2A 2A 41 43 45 2A 2A }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}