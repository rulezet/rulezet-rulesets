import "pe"
rule Upack_022_023_beta_Dwing_additional: PEiD
{
    strings:
        $a = { 6A 07 BE 88 01 40 00 AD 8B F8 59 95 F3 A5 AD B5 ?? F3 AB AD 50 97 51 58 8D 54 }
    condition:
        $a at pe.entry_point

}