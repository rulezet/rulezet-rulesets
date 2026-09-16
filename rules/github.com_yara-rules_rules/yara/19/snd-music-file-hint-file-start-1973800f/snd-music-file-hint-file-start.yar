import "pe"
rule SND_music_file_Hint_FILE_START: PEiD
{
    strings:
        $a = { 00 00 F8 2A ?? 00 }
    condition:
        $a at pe.entry_point

}