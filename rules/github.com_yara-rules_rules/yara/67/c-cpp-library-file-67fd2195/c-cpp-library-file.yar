import "pe"
rule C_Cpp_Library_file: PEiD
{
    strings:
        $a = { F0 0D 00 00 }
    condition:
        $a at pe.entry_point

}