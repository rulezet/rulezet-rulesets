import "pe"
rule _PseudoSigner_02_JDPack_1x_JDProtect_09_Anorganix: PEiD
{
    strings:
        $a = { 60 E8 22 00 00 00 5D 8B D5 81 ED 90 90 90 90 2B 95 90 90 90 90 81 EA 06 90 90 90 89 95 90 90 90 90 83 BD 45 00 01 00 01 }
    condition:
        $a at pe.entry_point

}