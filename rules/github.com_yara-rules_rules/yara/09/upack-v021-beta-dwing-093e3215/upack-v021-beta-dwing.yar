import "pe"
rule Upack_v021_Beta_Dwing: PEiD
{
    strings:
        $a = { BE 88 01 ?? ?? AD 8B F8 ?? ?? ?? ?? 33 }
    condition:
        $a at pe.entry_point

}