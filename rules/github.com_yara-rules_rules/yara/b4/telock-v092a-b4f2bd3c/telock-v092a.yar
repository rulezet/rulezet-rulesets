import "pe"
rule tElock_v092a: PEiD
{
    strings:
        $a = { E9 D5 E4 FF }
        $b = { E9 7E E9 FF FF 00 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}