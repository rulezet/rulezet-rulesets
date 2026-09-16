import "pe"
rule C_Cpp_Library_file_Hint_FILE_START: PEiD
{
    strings:
        $a = { F0 0D 00 00 }
    condition:
        $a at pe.entry_point

}