import "pe"
rule Windows_Group_file_Hint_FILE_START: PEiD
{
    strings:
        $a = { 50 4D 43 43 }
    condition:
        $a at pe.entry_point

}