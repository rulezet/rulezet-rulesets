import "pe"
rule XWD_graphics_format_Hint_FILE_START: PEiD
{
    strings:
        $a = { 00 00 00 71 00 00 00 07 00 00 00 02 00 00 00 }
    condition:
        $a at pe.entry_point

}