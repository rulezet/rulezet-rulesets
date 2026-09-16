import "pe"
rule PseudoSigner_02_Borland_Delphi_Setup_Module_Anorganix: PEiD
{
    strings:
        $a = { 55 8B EC 83 C4 90 53 56 57 33 C0 89 45 F0 89 45 D4 89 45 D0 E8 00 00 00 00 }
    condition:
        $a at pe.entry_point

}