import "pe"
rule _PseudoSigner_01_VOB_ProtectCD_5_Anorganix: PEiD
{
    strings:
        $a = { 36 3E 26 8A C0 60 E8 00 00 00 00 E9 }
    condition:
        $a at pe.entry_point

}