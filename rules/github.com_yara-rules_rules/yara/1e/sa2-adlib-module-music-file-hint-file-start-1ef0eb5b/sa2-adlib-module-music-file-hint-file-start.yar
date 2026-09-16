import "pe"
rule SA2_Adlib_Module_music_file_Hint_FILE_START: PEiD
{
    strings:
        $a = { 53 41 64 54 }
    condition:
        $a at pe.entry_point

}