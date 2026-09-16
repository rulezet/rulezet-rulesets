import "pe"
rule tElock_v07x_v084: PEiD
{
    strings:
        $a = { 60 E8 02 ?? ?? ?? CD 20 E8 ?? ?? ?? ?? 5E 2B C9 58 74 }
        $b = { 60 E8 00 00 C3 83 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}