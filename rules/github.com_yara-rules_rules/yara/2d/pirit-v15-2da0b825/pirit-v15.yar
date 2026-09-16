import "pe"
rule pirit_v15: PEiD
{
    strings:
        $a = { ?? ?? ?? 5B 24 55 50 44 FB 32 2E 31 5D }
        $b = { 5B 24 55 50 44 FB 32 2E 31 5D }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}