import "pe"
rule RPoly_crypt_10b_from_Vaska_18032007_1906: PEiD
{
    strings:
        $a = { E8 00 00 00 00 83 }
    condition:
        $a at pe.entry_point

}