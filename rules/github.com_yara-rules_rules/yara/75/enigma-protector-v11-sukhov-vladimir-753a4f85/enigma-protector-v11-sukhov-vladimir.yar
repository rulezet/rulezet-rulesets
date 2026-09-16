import "pe"
rule ENIGMA_Protector_V11_Sukhov_Vladimir: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 5D 83 ?? ?? 81 }
    condition:
        $a at pe.entry_point

}