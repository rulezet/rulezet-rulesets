import "pe"
rule Visual_Cpp_42_DLL: PEiD
{
    strings:
        $a = { 53 B8 01 00 00 00 8B 5C 24 0C 56 57 85 DB 55 75 12 83 3D 00 00 00 00 00 75 09 33 C0 5D 5F 5E 5B C2 0C 00 83 FB 01 74 05 83 FB 02 75 3A 8B 0D 00 00 00 00 85 C9 74 0F 8B 7C 24 1C 8B 74 24 14 57 53 56 FF D1 EB 08 8B 74 24 14 8B 7C 24 1C 85 C0 }
    condition:
        $a at pe.entry_point

}