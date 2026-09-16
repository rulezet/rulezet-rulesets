import "pe"
rule _PseudoSigner_01_REALBasic: PEiD
{
    strings:
        $a = { 55 89 E5 90 90 90 90 90 90 90 90 90 90 50 90 90 90 90 90 00 01 E9 }
    condition:
        $a at pe.entry_point

}