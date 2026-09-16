import "pe"
rule Visual_Cpp_2005_DLL_Microsoft: PEiD
{
    strings:
        $a = { 8B FF 55 8B EC 83 7D 0C 01 }
    condition:
        $a at pe.entry_point

}