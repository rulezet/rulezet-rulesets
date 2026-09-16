import "pe"
rule _PseudoSigner_02_MEW_11_SE_10: PEiD
{
    strings:
        $a = { E9 09 00 00 00 00 00 00 02 00 00 00 0C 90 }
    condition:
        $a at pe.entry_point

}