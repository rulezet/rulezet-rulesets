import "pe"
rule PseudoSigner_02_WATCOM_CCpp_EXE_Anorganix: PEiD
{
    strings:
        $a = { E9 00 00 00 00 90 90 90 90 57 41 }
    condition:
        $a at pe.entry_point

}