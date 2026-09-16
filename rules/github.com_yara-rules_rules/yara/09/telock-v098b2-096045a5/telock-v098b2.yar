import "pe"
rule tElock_v098b2: PEiD
{
    strings:
        $a = { E9 FF FF ?? ?? ?? ?? ?? ?? ?? }
        $b = { E9 1B E4 FF FF }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}