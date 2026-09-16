import "pe"
rule PseudoSigner_02_UPX_06_Anorganix: PEiD
{
    strings:
        $a = { 60 E8 00 00 00 00 58 83 E8 3D 50 8D B8 00 00 00 FF 57 8D B0 E8 00 00 00 }
    condition:
        $a at pe.entry_point

}