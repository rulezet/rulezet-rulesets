import "pe"
rule Microsoft_Visual_Cpp_42_DLL: PEiD
{
    strings:
        $a = { 53 B8 ?? ?? ?? ?? 8B ?? ?? ?? 56 57 85 DB 55 75 }
    condition:
        $a at pe.entry_point

}