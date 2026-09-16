import "pe"
rule _PseudoSigner_01_PENinja_131_Anorganix_additional: PEiD
{
    strings:
        $a = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 E9 }
    condition:
        $a at pe.entry_point

}