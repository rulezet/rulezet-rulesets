import "pe"
rule Microsoft_Visual_Cpp_v71_DLL: PEiD
{
    strings:
        $a = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 C4 E4 53 56 57 89 65 E8 C7 45 E4 01 00 00 00 C7 45 FC }
        $b = { 55 8B EC 53 8B 5D 08 56 8B 75 0C 85 F6 57 8B 7D 10 75 09 83 3D ?? ?? 40 00 00 EB 26 83 FE 01 74 05 83 FE 02 75 22 A1 }
    condition:
        for any of ($*) : ( $ at pe.entry_point )

}