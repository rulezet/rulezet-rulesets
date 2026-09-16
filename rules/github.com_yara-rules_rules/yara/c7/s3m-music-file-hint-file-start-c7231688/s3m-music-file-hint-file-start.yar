import "pe"
rule S3M_music_file_Hint_FILE_START: PEiD
{
    strings:
        $a = { 53 43 52 4D }
    condition:
        $a at pe.entry_point

}