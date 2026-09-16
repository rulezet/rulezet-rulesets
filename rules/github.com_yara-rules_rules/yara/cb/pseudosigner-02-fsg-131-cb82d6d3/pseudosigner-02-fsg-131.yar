import "pe"
rule PseudoSigner_02_FSG_131: PEiD
{
    strings:
        $a = { BE 90 90 90 00 BF 90 90 90 00 BB 90 90 90 00 53 BB 90 90 90 00 B2 80 }
    condition:
        $a at pe.entry_point

}