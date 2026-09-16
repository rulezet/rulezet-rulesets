import "pe"
rule HSC_music_file_Hint_FILE_START: PEiD
{
    strings:
        $a = { C8 E2 04 20 }
    condition:
        $a at pe.entry_point

}