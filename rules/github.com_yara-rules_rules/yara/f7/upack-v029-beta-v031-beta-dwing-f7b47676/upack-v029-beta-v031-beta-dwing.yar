import "pe"
rule Upack_v029_Beta_v031_Beta_Dwing: PEiD
{
    strings:
        $a = { BE 88 01 ?? ?? AD 8B F8 95 AD 91 F3 A5 AD B5 ?? F3 }
    condition:
        $a at pe.entry_point

}