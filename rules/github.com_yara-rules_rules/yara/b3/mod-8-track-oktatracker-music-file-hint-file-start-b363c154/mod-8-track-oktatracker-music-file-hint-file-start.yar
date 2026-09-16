import "pe"
rule MOD_8_Track_Oktatracker_music_file_Hint_FILE_START: PEiD
{
    strings:
        $a = { 4F 43 54 }
    condition:
        $a at pe.entry_point

}