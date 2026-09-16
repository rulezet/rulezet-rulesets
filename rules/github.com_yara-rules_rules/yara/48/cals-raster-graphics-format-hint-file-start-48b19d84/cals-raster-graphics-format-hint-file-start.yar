import "pe"
rule CALS_Raster_graphics_format_Hint_FILE_START: PEiD
{
    strings:
        $a = { 73 72 63 64 6F 63 69 64 3A 20 }
    condition:
        $a at pe.entry_point

}