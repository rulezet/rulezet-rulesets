import "pe"
rule Upack_v036_alpha_Sign_by_hot_UNP: PEiD
{
    strings:
        $a = { AB E2 E5 5D 59 8B 76 68 51 59 46 AD 85 C0 }
    condition:
        $a at pe.entry_point

}