import "pe"
rule PseudoSigner_02_Borland_Delphi_DLL: PEiD
{
    strings:
        $a = { 55 8B EC 83 C4 B4 B8 90 90 90 90 E8 00 00 00 00 E8 00 00 00 00 8D 40 00 }
    condition:
        $a at pe.entry_point

}