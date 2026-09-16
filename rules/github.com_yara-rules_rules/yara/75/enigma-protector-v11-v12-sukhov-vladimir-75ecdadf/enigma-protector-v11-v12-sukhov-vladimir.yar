import "pe"
rule ENIGMA_Protector_V11_V12_Sukhov_Vladimir: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 5D 83 ED 06 81 }
    condition:
        $a at pe.entry_point

}