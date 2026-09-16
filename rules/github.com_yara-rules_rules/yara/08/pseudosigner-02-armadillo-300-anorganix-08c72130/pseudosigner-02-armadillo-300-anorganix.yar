import "pe"
rule _PseudoSigner_02_Armadillo_300_Anorganix: PEiD
{
    strings:
        $a = { 60 E8 2A 00 00 00 5D 50 51 EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 59 58 50 51 EB 85 }
    condition:
        $a at pe.entry_point

}