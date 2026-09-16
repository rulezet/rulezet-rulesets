import "pe"
rule Pelles_C_290_300_400_DLL_X86_CRT_LIB_additional: PEiD
{
    strings:
        $a = { 55 89 E5 53 56 57 8B 5D 0C 8B 75 10 BF 01 00 00 00 85 DB 75 10 83 3D ?? ?? ?? ?? 00 75 07 31 C0 E9 ?? ?? ?? ?? 83 FB 01 74 05 83 FB 02 75 ?? 85 FF 74 }
    condition:
        $a at pe.entry_point

}