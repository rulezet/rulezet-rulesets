import "pe"
rule RPoly_crypt_10b_from_Vaska_18032007_1905: PEiD
{
    strings:
        $a = { 83 04 24 05 C3 60 }
    condition:
        $a at pe.entry_point

}