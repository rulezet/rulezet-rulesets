import "pe"
rule Windows_Write_file_Hint_FILE_START: PEiD
{
    strings:
        $a = { BE 00 00 00 AB 00 00 00 }
    condition:
        $a at pe.entry_point

}