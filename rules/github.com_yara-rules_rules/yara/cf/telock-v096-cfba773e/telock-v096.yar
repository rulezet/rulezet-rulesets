import "pe"
rule tElock_v096: PEiD
{
    strings:
        $a = { E9 25 E4 FF FF ?? ?? ?? }
        $b = { E9 59 E4 FF FF 00 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}