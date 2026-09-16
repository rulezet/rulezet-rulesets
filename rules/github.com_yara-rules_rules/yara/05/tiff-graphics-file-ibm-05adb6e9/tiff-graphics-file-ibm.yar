import "pe"
rule TIFF_Graphics_file_IBM: PEiD
{
    strings:
        $a = { 49 49 2A }
    condition:
        $a at pe.entry_point

}