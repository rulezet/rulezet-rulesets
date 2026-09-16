import "pe"
rule _PseudoSigner_02_Yodas_Protector_102_Anorganix_additional: PEiD
{
    strings:
        $a = { E8 03 00 00 00 EB 01 90 90 }
    condition:
        $a at pe.entry_point

}