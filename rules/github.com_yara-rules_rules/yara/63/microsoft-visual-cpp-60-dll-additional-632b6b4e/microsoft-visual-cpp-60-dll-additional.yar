import "pe"
rule Microsoft_Visual_Cpp_60_DLL_additional: PEiD
{
    strings:
        $a = { 55 8B EC 53 8B 5D 08 56 8B 75 0C 57 8B 7D 10 85 F6 75 09 83 3D ?? ?? ?? ?? ?? EB 26 83 FE 01 74 05 83 FE 02 75 22 A1 ?? ?? ?? ?? 85 C0 74 09 57 56 53 FF D0 85 C0 74 0C 57 56 53 E8 15 FF FF FF 85 C0 75 04 33 C0 EB 4E }
    condition:
        $a at pe.entry_point

}