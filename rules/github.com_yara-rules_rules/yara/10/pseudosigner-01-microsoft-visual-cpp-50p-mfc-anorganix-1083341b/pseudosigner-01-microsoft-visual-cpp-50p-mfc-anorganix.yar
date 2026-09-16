import "pe"
rule _PseudoSigner_01_Microsoft_Visual_Cpp_50p_MFC_Anorganix: PEiD
{
    strings:
        $a = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 E9 }
    condition:
        $a at pe.entry_point

}