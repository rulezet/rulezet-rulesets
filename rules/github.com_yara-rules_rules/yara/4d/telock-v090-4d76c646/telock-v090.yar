import "pe"
rule tElock_v090: PEiD
{
    strings:
        $a = { ?? ?? E8 02 00 00 00 E8 00 E8 00 00 00 00 5E 2B }
        $b = { E8 02 00 00 00 E8 00 E8 00 00 00 00 5E 2B }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}