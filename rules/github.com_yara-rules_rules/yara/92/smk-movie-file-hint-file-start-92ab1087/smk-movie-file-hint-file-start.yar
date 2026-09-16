import "pe"
rule SMK_movie_file_Hint_FILE_START: PEiD
{
    strings:
        $a = { 53 4D 4B 32 }
    condition:
        $a at pe.entry_point

}