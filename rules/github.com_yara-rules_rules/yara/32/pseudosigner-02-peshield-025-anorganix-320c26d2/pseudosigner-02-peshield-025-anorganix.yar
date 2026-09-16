import "pe"
rule _PseudoSigner_02_PESHiELD_025_Anorganix: PEiD
{
    strings:
        $a = { 60 E8 2B 00 00 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 CC CC }
    condition:
        $a at pe.entry_point

}