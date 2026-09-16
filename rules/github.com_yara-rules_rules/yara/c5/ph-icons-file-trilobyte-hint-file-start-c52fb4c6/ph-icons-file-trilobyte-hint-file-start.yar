import "pe"
rule PH_Icons_file_Trilobyte_Hint_FILE_START: PEiD
{
    strings:
        $a = { 69 63 6F 6E 01 00 10 00 10 }
    condition:
        $a at pe.entry_point

}