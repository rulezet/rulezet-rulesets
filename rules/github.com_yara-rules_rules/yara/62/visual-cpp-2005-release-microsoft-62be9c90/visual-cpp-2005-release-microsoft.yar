import "pe"
rule Visual_Cpp_2005_Release_Microsoft: PEiD
{
    strings:
        $a = { E8 ?? ?? ?? ?? E9 ?? FD FF FF }
    condition:
        $a at pe.entry_point

}