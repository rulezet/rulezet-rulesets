import "pe"
rule PC_Shrinker_v045: PEiD
{
    strings:
        $a = { ?? BD ?? ?? ?? ?? 01 AD E3 38 40 ?? FF B5 DF 38 40 }
        $b = { BD ?? ?? ?? ?? 01 AD E3 38 40 ?? FF B5 DF 38 40 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}