import "pe"
rule PseudoSigner_02_CD_Cops_II_Anorganix: PEiD
{
    strings:
        $a = { 53 60 BD 90 90 90 90 8D 45 90 8D 5D 90 E8 00 00 00 00 8D 01 }
    condition:
        $a at pe.entry_point

}