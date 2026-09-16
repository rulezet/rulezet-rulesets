import "pe"
rule PDS_graphics_file_format_Hint_FILE_START: PEiD
{
    strings:
        $a = { 49 4D 41 47 45 49 44 45 4E 54 49 46 49 45 52 20 }
    condition:
        $a at pe.entry_point

}