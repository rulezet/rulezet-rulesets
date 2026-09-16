import "pe"
rule PC_Shrinker_v029: PEiD
{
    strings:
        $a = { ?? BD ?? ?? ?? ?? 01 AD 55 39 40 ?? 8D B5 35 39 40 }
        $b = { BD ?? ?? ?? ?? 01 AD 55 39 40 ?? 8D B5 35 39 40 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}