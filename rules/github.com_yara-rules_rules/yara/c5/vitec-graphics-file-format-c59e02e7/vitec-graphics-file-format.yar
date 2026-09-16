import "pe"
rule VITec_graphics_file_format: PEiD
{
    strings:
        $a = { 00 5B 07 20 00 00 00 2C }
    condition:
        $a at pe.entry_point

}