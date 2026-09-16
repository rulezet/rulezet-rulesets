import "pe"
rule MPEG_movie_file_Hint_FILE_START: PEiD
{
    strings:
        $a = { 00 00 01 BA 2F FF FD E6 C1 80 18 61 00 00 01 BB }
    condition:
        $a at pe.entry_point

}