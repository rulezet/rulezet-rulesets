import "pe"
rule Pelles_C_450_DLL_X86_CRT_LIB: PEiD
{
    strings:
        $a = { 55 89 E5 53 56 57 8B 5D 0C 8B 75 10 85 DB 75 0D 83 3D ?? ?? ?? ?? 00 75 04 31 C0 EB 57 83 FB 01 74 05 83 FB 02 75 }
    condition:
        $a at pe.entry_point

}