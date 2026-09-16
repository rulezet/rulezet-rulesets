import "pe"
rule PseudoSigner_02_Borland_Cpp_DLL_Method_2_Anorganix: PEiD
{
    strings:
        $a = { EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 E9 90 90 90 90 }
    condition:
        $a at pe.entry_point

}