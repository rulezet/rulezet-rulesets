import "pe"
rule Warning_may_be_RCryptor_by_Vaska_unknown_ver_21032006_2318: PEiD
{
    strings:
        $a = { C0 14 13 74 06 80 30 }
    condition:
        $a at pe.entry_point

}