import "pe"
rule Upack_v022_v023_Beta_Dwing: PEiD
{
    strings:
        $a = { 6A 07 BE 88 01 40 00 AD 8B F8 59 95 F3 A5 }
    condition:
        $a at pe.entry_point

}