import "pe"
rule tElock_v098b1: PEiD
{
    strings:
        $a = { E9 1B E4 FF }
        $b = { E9 25 E4 FF FF }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}