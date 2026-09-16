import "pe"
rule WarWind_Save_file_Hint_FILE_START: PEiD
{
    strings:
        $a = { 57 41 52 53 41 56 }
    condition:
        $a at pe.entry_point

}