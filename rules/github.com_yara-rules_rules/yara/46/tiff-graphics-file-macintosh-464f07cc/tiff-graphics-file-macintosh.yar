import "pe"
rule TIFF_Graphics_file_Macintosh: PEiD
{
    strings:
        $a = { 4D 4D 00 }
    condition:
        $a at pe.entry_point

}