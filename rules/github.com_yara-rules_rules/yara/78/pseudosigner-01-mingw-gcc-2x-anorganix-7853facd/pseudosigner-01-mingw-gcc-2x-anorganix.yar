import "pe"
rule PseudoSigner_01_MinGW_GCC_2x_Anorganix: PEiD
{
    strings:
        $a = { 55 89 E5 E8 02 00 00 00 C9 C3 90 90 45 58 45 E9 }
    condition:
        $a at pe.entry_point

}