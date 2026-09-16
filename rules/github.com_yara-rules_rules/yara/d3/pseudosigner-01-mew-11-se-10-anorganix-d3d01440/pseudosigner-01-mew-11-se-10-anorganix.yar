import "pe"
rule _PseudoSigner_01_MEW_11_SE_10_Anorganix: PEiD
{
    strings:
        $a = { E9 09 00 00 00 00 00 00 02 00 00 00 0C 90 E9 }
    condition:
        $a at pe.entry_point

}