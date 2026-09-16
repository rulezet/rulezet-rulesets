import "pe"
rule HP_48sx_graphics_format_Hint_FILE_START: PEiD
{
    strings:
        $a = { 48 50 48 50 34 38 2D 41 }
    condition:
        $a at pe.entry_point

}