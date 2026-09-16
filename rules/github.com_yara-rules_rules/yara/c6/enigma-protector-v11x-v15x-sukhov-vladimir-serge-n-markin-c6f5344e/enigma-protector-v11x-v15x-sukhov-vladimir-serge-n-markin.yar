import "pe"
rule Enigma_Protector_V11X_V15X_Sukhov_Vladimir_Serge_N_Markin: PEiD
{
    strings:
        $a = { 55 8B EC 83 C4 F0 B8 00 10 40 00 E8 01 00 00 00 9A 83 C4 10 8B E5 5D E9 }
    condition:
        $a at pe.entry_point

}