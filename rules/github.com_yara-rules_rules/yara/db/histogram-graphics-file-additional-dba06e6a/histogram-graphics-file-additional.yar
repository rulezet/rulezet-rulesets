import "pe"
rule Histogram_graphics_file_additional: PEiD
{
    strings:
        $a = { 6D 68 77 61 6E 68 00 04 01 02 01 02 }
    condition:
        $a at pe.entry_point

}