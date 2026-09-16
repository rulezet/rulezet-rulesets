import "pe"
rule MPEG_Video_file_2_Hint_FILE_START: PEiD
{
    strings:
        $a = { 00 00 01 B3 }
    condition:
        $a at pe.entry_point

}