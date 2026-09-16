import "pe"
rule Microsoft_Visual_Cpp_v71_EXE: PEiD
{
    strings:
        $a = { 6A ?? 68 ?? ?? ?? 01 E8 ?? ?? 00 00 66 81 3D 00 00 00 01 4D 5A 75 ?? A1 3C 00 00 01 ?? ?? 00 00 00 01 }
    condition:
        $a at pe.entry_point

}