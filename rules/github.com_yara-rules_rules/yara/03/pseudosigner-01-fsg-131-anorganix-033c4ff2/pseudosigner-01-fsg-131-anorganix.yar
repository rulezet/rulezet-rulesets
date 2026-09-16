import "pe"
rule _PseudoSigner_01_FSG_131_Anorganix: PEiD
{
    strings:
        $a = { BE 90 90 90 00 BF 90 90 90 00 BB 90 90 90 00 53 BB 90 90 90 00 B2 80 E9 }
    condition:
        $a at pe.entry_point

}