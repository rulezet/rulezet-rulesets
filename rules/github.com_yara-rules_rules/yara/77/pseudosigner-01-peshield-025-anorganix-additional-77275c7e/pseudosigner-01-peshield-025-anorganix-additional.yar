import "pe"
rule _PseudoSigner_01_PESHiELD_025_Anorganix_additional: PEiD
{
    strings:
        $a = { 60 E8 2B 00 00 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 CC CC E9 }
    condition:
        $a at pe.entry_point

}