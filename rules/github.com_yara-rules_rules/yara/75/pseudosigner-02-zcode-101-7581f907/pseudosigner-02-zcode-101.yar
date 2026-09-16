import "pe"
rule PseudoSigner_02_ZCode_101: PEiD
{
    strings:
        $a = { E9 12 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 E9 FB FF FF FF C3 68 00 00 00 00 64 FF 35 00 00 00 00 }
    condition:
        $a at pe.entry_point

}