import "pe"
rule Microsoft_Visual_Cpp_70_80: PEiD
{
    strings:
        $a = { 53 56 8B 44 24 18 0B C0 75 18 8B 4C 24 14 8B 44 24 10 33 D2 F7 F1 8B D8 8B 44 24 0C F7 F1 8B D3 EB 41 8B C8 8B 5C 24 14 8B 54 24 10 8B 44 24 0C D1 E9 D1 DB D1 EA D1 D8 0B C9 75 F4 F7 F3 8B F0 F7 64 24 18 8B C8 8B 44 24 14 F7 E6 03 D1 72 0E 3B 54 24 10 77 08 72 07 }
    condition:
        $a at pe.entry_point

}