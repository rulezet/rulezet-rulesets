import "pe"
rule Upack_01x_020_021_024_beta_Dwing_additional: PEiD
{
    strings:
        $a = { BE 88 01 ?? ?? AD 8B F8 ?? ?? ?? ?? 33 }
    condition:
        $a at pe.entry_point

}