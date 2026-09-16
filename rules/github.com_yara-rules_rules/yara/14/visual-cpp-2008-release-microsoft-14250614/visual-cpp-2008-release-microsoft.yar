import "pe"
rule Visual_Cpp_2008_Release_Microsoft: PEiD
{
    strings:
        $a = { E8 ?? ?? ?? ?? E9 A4 FE FF FF }
    condition:
        $a at pe.entry_point

}