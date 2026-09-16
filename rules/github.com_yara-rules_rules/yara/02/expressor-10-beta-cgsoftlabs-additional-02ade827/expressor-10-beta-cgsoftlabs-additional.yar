import "pe"
rule eXPressor_10_beta_CGSoftLabs_additional: PEiD
{
    strings:
        $a = { E8 53 03 00 00 8B F0 56 56 E8 98 03 00 00 8B C8 }
    condition:
        $a at pe.entry_point

}