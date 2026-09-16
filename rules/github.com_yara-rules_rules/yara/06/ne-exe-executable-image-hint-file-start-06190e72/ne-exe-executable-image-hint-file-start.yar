import "pe"
rule NE_Exe_Executable_Image_Hint_FILE_START: PEiD
{
    strings:
        $a = { 4E 45 }
    condition:
        $a at pe.entry_point

}