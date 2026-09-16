import "pe"
rule PseudoSigner_01_PENinja_131_Anorganix: PEiD
{
    strings:
        $a = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 E9 }
    condition:
        $a at pe.entry_point

}