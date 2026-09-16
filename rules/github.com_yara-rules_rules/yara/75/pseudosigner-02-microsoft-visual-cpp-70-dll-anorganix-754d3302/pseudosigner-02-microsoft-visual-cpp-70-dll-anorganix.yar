import "pe"
rule _PseudoSigner_02_Microsoft_Visual_Cpp_70_DLL_Anorganix: PEiD
{
    strings:
        $a = { 55 8D 6C 01 00 81 EC 00 00 00 00 8B 45 90 83 F8 01 56 0F 84 00 00 00 00 85 C0 0F 84 }
    condition:
        $a at pe.entry_point

}