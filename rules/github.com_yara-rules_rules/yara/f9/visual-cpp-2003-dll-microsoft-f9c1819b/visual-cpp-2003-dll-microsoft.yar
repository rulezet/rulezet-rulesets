import "pe"
rule Visual_Cpp_2003_DLL_Microsoft: PEiD
{
    strings:
        $a = { 8B FF 55 8B EC }
    condition:
        $a at pe.entry_point

}