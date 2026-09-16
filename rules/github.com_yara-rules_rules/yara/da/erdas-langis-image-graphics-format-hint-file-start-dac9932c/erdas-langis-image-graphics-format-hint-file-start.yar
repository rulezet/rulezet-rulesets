import "pe"
rule Erdas_LANGIS_Image_graphics_format_Hint_FILE_START: PEiD
{
    strings:
        $a = { 48 45 41 44 37 34 00 00 03 00 }
    condition:
        $a at pe.entry_point

}