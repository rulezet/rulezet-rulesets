import "pe"
rule Upack_v021Beta_Sign_by_hot_UNP_additional: PEiD
{
    strings:
        $a = { BE 88 01 ?? ?? AD 8B F8 ?? ?? ?? ?? 33 }
    condition:
        $a at pe.entry_point

}