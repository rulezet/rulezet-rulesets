import "pe"
rule Borland_Cpp_additional: PEiD
{
    strings:
        $a = { A1 ?? ?? ?? ?? C1 E0 02 A3 }
    condition:
        $a at pe.entry_point

}