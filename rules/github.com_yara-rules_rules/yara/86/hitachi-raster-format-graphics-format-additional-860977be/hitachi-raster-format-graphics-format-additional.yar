import "pe"
rule Hitachi_Raster_Format_graphics_format_additional: PEiD
{
    strings:
        $a = { 43 41 44 43 2F 4B 52 20 52 53 54 }
    condition:
        $a at pe.entry_point

}