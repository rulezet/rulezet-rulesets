import "pe"
rule _PseudoSigner_01_Yodas_Protector_102_Anorganix: PEiD
{
    strings:
        $a = { E8 03 00 00 00 EB 01 90 90 E9 }
    condition:
        $a at pe.entry_point

}