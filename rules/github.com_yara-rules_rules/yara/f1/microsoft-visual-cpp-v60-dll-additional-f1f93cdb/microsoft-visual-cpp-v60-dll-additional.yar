import "pe"
rule Microsoft_Visual_Cpp_v60_DLL_additional: PEiD
{
    strings:
        $a = { 8B 44 ?? 08 }
    condition:
        $a at pe.entry_point

}