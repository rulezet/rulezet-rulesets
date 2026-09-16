import "pe"
rule AVI_movie_file_Hint_FILE_START: PEiD
{
    strings:
        $a = { 52 49 46 46 ?? ?? ?? ?? 41 56 49 ?? 4C 49 53 54 }
    condition:
        $a at pe.entry_point

}