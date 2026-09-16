import "pe"
rule ZM_Exe_Executable_Image_Hint_FILE_START: PEiD
{
    strings:
        $a = { 5A 4D }
    condition:
        $a at pe.entry_point

}