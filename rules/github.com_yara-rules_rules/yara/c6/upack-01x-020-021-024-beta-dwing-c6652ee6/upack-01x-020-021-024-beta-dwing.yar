import "pe"
rule Upack_01x_020_021_024_beta_Dwing: PEiD
{
    strings:
        $a = { BE 88 01 ?? ?? AD 8B F8 ?? ?? ?? ?? 33 }
        $b = { BE ?? 01 40 00 AD 8B F8 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}