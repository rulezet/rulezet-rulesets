import "pe"
rule RIX_graphics_file_Hint_FILE_START: PEiD
{
    strings:
        $a = { 52 49 58 33 }
    condition:
        $a at pe.entry_point

}