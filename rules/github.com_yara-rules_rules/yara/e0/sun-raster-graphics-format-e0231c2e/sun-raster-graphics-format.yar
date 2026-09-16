import "pe"
rule Sun_Raster_Graphics_format: PEiD
{
    strings:
        $a = { 59 A6 6A 95 }
    condition:
        $a at pe.entry_point

}