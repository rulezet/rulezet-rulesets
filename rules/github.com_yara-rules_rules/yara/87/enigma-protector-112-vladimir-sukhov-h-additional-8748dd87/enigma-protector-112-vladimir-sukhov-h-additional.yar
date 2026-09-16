import "pe"
rule Enigma_protector_112_Vladimir_Sukhov_h_additional: PEiD
{
    strings:
        $a = { 55 46 41 C6 D2 C1 00 00 }
    condition:
        $a at pe.entry_point

}