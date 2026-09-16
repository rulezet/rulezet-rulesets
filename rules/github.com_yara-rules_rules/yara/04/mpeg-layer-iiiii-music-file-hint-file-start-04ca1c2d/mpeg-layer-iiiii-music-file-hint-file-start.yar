import "pe"
rule MPEG_Layer_IIIII_music_file_Hint_FILE_START: PEiD
{
    strings:
        $a = { FF E3 }
    condition:
        $a at pe.entry_point

}