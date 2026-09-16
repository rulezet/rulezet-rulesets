import "pe"
rule ENIGMA_Protector_V11_CracKed_By_shoooo_fly_Sukhov_Vladimir_additional: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 5D 83 C5 FA 81 }
    condition:
        $a at pe.entry_point

}