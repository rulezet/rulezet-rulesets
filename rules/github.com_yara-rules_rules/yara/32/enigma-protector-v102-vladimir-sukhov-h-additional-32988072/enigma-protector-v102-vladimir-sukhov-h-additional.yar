import "pe"
rule Enigma_protector_v102_Vladimir_Sukhov_h_additional: PEiD
{
    strings:
        $a = { 55 53 20 50 54 4F 20 00 }
    condition:
        $a at pe.entry_point

}