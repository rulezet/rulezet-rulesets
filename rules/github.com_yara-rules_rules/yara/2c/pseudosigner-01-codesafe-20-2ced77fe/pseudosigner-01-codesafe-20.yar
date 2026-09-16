import "pe"
rule _PseudoSigner_01_CodeSafe_20: PEiD
{
    strings:
        $a = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 0B 83 EC 10 53 56 57 E8 C4 01 00 85 E9 }
    condition:
        $a at pe.entry_point

}