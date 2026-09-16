import "pe"
rule XM_music_file_Hint_FILE_START: PEiD
{
    strings:
        $a = { 45 78 74 65 6E 64 65 64 20 4D 6F 64 75 6C 65 3A }
    condition:
        $a at pe.entry_point

}