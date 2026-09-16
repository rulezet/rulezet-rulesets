import "pe"
rule Microsoft_Visual_Cpp_60_80_additional: PEiD
{
    strings:
        $a = { 3D 00 10 00 00 73 0E F7 D8 03 C4 83 C0 04 85 00 94 8B 00 50 C3 51 8D 4C 24 08 81 E9 00 10 00 00 2D 00 10 00 00 85 01 3D 00 10 00 00 73 EC 2B C8 8B C4 85 01 8B E1 8B 08 8B 40 04 50 C3 }
    condition:
        $a at pe.entry_point

}