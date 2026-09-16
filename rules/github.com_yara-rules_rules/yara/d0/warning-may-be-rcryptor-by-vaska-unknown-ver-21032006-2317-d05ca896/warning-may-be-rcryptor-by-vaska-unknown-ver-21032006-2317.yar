import "pe"
rule Warning_may_be_RCryptor_by_Vaska_unknown_ver_21032006_2317: PEiD
{
    strings:
        $a = { EB F3 E8 00 00 00 00 C3 }
    condition:
        $a at pe.entry_point

}