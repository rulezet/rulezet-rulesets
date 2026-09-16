import "pe"
rule Upack_v035_alpha_Sign_by_hot_UNP: PEiD
{
    strings:
        $a = { 8B F2 8B CA 03 4C 19 1C 03 54 1A 20 }
    condition:
        $a at pe.entry_point

}