import "pe"
rule MPEG_Layer_IIIII_music_file_Hint_FILE_START_additional: PEiD
{
    strings:
        $a = { FF FE }
    condition:
        $a at pe.entry_point

}