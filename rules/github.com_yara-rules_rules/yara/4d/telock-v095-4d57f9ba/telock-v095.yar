import "pe"
rule tElock_v095: PEiD
{
    strings:
        $a = { E9 59 E4 FF }
        $b = { E9 D5 E4 FF FF 00 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}