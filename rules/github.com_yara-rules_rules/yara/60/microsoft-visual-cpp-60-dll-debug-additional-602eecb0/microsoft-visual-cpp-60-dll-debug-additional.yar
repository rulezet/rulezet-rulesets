import "pe"
rule Microsoft_Visual_Cpp_60_DLL_Debug_additional: PEiD
{
    strings:
        $a = { 8B 44 24 08 8B 4C 24 10 0B C8 8B 4C 24 0C 75 09 8B 44 24 04 F7 E1 C2 10 00 53 F7 E1 8B D8 8B 44 24 08 F7 64 24 14 03 D8 8B 44 24 08 F7 E1 03 D3 5B C2 10 00 }
    condition:
        $a at pe.entry_point

}