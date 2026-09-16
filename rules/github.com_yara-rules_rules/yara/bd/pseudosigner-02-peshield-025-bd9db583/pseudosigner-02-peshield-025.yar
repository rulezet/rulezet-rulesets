import "pe"
rule PseudoSigner_02_PESHiELD_025: PEiD
{
    strings:
        $a = { 60 E8 2B 00 00 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 CC CC }
    condition:
        $a at pe.entry_point

}