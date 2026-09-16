import "pe"
rule PseudoSigner_02_PE_Intro_10_Anorganix: PEiD
{
    strings:
        $a = { 8B 04 24 9C 60 E8 14 00 00 00 5D 81 ED 0A 45 40 90 80 BD 67 44 40 90 90 0F 85 48 FF ED 0A }
    condition:
        $a at pe.entry_point

}