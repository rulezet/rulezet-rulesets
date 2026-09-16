import "pe"
rule Kodak_Color_management_for_Windows_file_Hint_FILE_START: PEiD
{
    strings:
        $a = { 4B 43 4D 53 }
    condition:
        $a at pe.entry_point

}